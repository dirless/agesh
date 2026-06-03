module AgeSh
  # Fork, set user credentials, and exec a command with piped stdin/stdout.
  # No PTY — used for command mode (rsync, etc.).
  # The child process must call execve immediately — no Crystal runtime after fork.
  module ExecSession
    # Result of spawning a command with pipes.
    struct ExecResult
      getter child_pid : Int32
      getter stdin_fd : Int32  # write end — write data here to send to child's stdin
      getter stdout_fd : Int32 # read end — read from here to get child's stdout

      def initialize(@child_pid : Int32, @stdin_fd : Int32, @stdout_fd : Int32)
      end
    end

    # Spawn a command with piped stdin/stdout.
    # All Crystal heap allocations happen in the parent before fork.
    # Returns ExecResult with pipe fds and child pid.
    def self.spawn_with_pipes(
      command : String,
      user_info : UserInfo,
      env : Hash(String, String) = {} of String => String,
    ) : ExecResult
      argv_tokens = parse_argv(command)
      raise Error.new("Empty command") if argv_tokens.empty?

      # --- PARENT: build all C data before fork ---
      envp = UserSession.build_env(user_info, "", env)

      # Build null-terminated C argv
      c_argv = argv_tokens.map(&.to_unsafe)
      c_argv << Pointer(UInt8).null

      # Create pipe pairs
      stdin_fds = uninitialized LibC::Int[2]
      stdout_fds = uninitialized LibC::Int[2]
      raise Error.new("pipe(stdin) failed: #{Errno.value}") if LibC.pipe(stdin_fds) < 0
      raise Error.new("pipe(stdout) failed: #{Errno.value}") if LibC.pipe(stdout_fds) < 0

      pid = LibC.fork
      raise Error.new("fork failed: #{Errno.value}") if pid < 0

      if pid == 0
        # === CHILD PROCESS — no Crystal GC calls past this point ===
        LibC.prctl(LibC::PR_SET_PDEATHSIG, 9_u64)
        LibC.setsid

        # Wire up pipes: child reads from stdin, writes to stdout
        LibC.close(stdin_fds[1])  # close write end of stdin pipe
        LibC.close(stdout_fds[0]) # close read end of stdout pipe

        LibC.dup2(stdin_fds[0], 0)
        LibC.dup2(stdout_fds[1], 1)
        LibC.dup2(stdout_fds[1], 2) # merge stderr into stdout

        # Close original pipe fds now that they're duped
        LibC.close(stdin_fds[0]) if stdin_fds[0] > 2
        LibC.close(stdout_fds[1]) if stdout_fds[1] > 2

        home_str = (user_info.home || "/")
        # Privilege drop only works if running as root; skip if already the target user.
        if LibC.getuid == 0
          LibC._exit(1) if LibC.setgid(user_info.gid) < 0
          LibC._exit(1) if LibC.initgroups(user_info.username, user_info.gid) < 0
          LibC._exit(1) if LibC.setuid(user_info.uid) < 0
        end
        LibC.chdir(home_str) unless home_str.empty?

        # Try execvp first (searches PATH), fall back to execve with full path
        LibC.execvp(argv_tokens[0], c_argv.to_unsafe)
        LibC.execve(argv_tokens[0], c_argv.to_unsafe, envp.to_unsafe)
        LibC._exit(127)
      else
        # === PARENT PROCESS ===
        LibC.close(stdin_fds[0])  # close read end of stdin pipe
        LibC.close(stdout_fds[1]) # close write end of stdout pipe

        Logger.debug("Exec spawned: pid=#{pid} cmd=#{command}")
        ExecResult.new(pid, stdin_fds[1], stdout_fds[0])
      end
    end

    # Check if a command exists in PATH. Returns true if any PATH component
    # contains an executable file matching the command name.
    def self.command_exists?(command : String) : Bool
      # If the command contains a path separator, check directly
      if command.includes?('/') || command.includes?('\\')
        return LibC.access(command, LibC::X_OK) == 0
      end

      # Scan PATH directories
      path_env = ENV["PATH"]? || "/usr/local/bin:/usr/bin:/bin"
      path_env.split(':') do |dir|
        next if dir.empty?
        full = "#{dir}/#{command}"
        return true if LibC.access(full, LibC::X_OK) == 0
      end
      false
    end

    # Simple argv parser: splits on whitespace with single/double quote support.
    # No escape sequences. Runs in the parent before fork so GC allocations are fine.
    private def self.parse_argv(command : String) : Array(String)
      tokens = [] of String
      current = String::Builder.new
      in_quote : Char? = nil

      command.each_char do |c|
        if in_quote
          if c == in_quote
            in_quote = nil
          else
            current << c
          end
        elsif c == '\'' || c == '"'
          in_quote = c
        elsif c.whitespace?
          s = current.to_s
          unless s.empty?
            tokens << s
            current = String::Builder.new
          end
        else
          current << c
        end
      end

      s = current.to_s
      tokens << s unless s.empty?
      tokens
    end
  end
end
