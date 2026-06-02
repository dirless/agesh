module AgeSh
  # Fork, set user credentials, and exec the target user's shell.
  # The child process must call execve immediately — no Crystal runtime after fork.
  module UserSession
    # Spawn a shell session with an explicit master_fd (caller allocates PTY).
    # Returns child_pid.
    #
    # All Crystal heap allocations (strings, arrays, hashes) are done in the
    # PARENT before fork so the child can go straight to execve using only
    # raw LibC calls. Crystal's GC is not fork-safe.
    def self.spawn_with_master(
      master_fd : Int32,
      slave_path : String,
      user_info : UserInfo,
      term_type : String,
      rows : UInt32,
      cols : UInt32,
      env : Hash(String, String) = {} of String => String,
    ) : Int32
      # --- PARENT: build all C data before fork ---
      shell_str = user_info.shell || "/bin/sh"
      home_str = user_info.home || "/"
      envp = build_env(user_info, term_type, env)         # Array(Pointer(UInt8)), null-terminated
      c_argv = [shell_str.to_unsafe, Pointer(UInt8).null] # null-terminated argv

      slave_fd = LibC.open(slave_path, LibC::O_RDWR)
      raise Error.new("Failed to open slave PTY: #{Errno.value}") if slave_fd < 0

      pid = LibC.fork
      raise Error.new("fork failed: #{Errno.value}") if pid < 0

      if pid == 0
        # === CHILD PROCESS — no Crystal GC calls past this point ===
        # Die with the parent if it crashes (SIGKILL = 9).
        LibC.prctl(LibC::PR_SET_PDEATHSIG, 9_u64)

        LibC.setsid
        ret = LibC.ioctl(slave_fd, LibC::TIOCSCTTY, 0)
        LibC._exit(1) if ret < 0

        ws = PTY::Winsize.new(rows.to_u16, cols.to_u16) # struct on stack — no GC
        LibC.ioctl(slave_fd, LibC::TIOCSWINSZ, pointerof(ws).as(Void*))

        LibC.dup2(slave_fd, 0)
        LibC.dup2(slave_fd, 1)
        LibC.dup2(slave_fd, 2)
        LibC.close(slave_fd) if slave_fd > 2

        LibC._exit(1) if LibC.setgid(user_info.gid) < 0
        LibC._exit(1) if LibC.initgroups(user_info.username, user_info.gid) < 0
        LibC._exit(1) if LibC.setuid(user_info.uid) < 0

        LibC.chdir(home_str) unless home_str.empty? # home_str allocated in parent — safe

        LibC.execve(shell_str, c_argv.to_unsafe, envp.to_unsafe)
        LibC._exit(127)
      else
        # === PARENT PROCESS ===
        LibC.close(slave_fd)
        Logger.debug("Child process spawned: pid=#{pid}")
        pid
      end
    end

    # Wait for a child process to exit. Returns exit status.
    def self.wait(pid : Int32) : Int32
      status = 0
      LibC.waitpid(pid, pointerof(status), 0)
      status
    end

    private def self.build_env(user_info : UserInfo, term_type : String, extra : Hash(String, String)) : Array(Pointer(UInt8))
      base = {
        "TERM"    => term_type,
        "HOME"    => user_info.home || "/",
        "USER"    => user_info.username,
        "LOGNAME" => user_info.username,
        "SHELL"   => user_info.shell || "/bin/sh",
        "PATH"    => ENV["PATH"]? || "/usr/local/bin:/usr/bin:/bin",
        "LANG"    => ENV["LANG"]? || "en_US.UTF-8",
      }

      # Merge extra env vars
      base.merge!(extra)

      # Build C envp array (null-terminated).
      # Keep the String objects alive in `entries` so .to_unsafe pointers remain valid.
      entries = base.map { |k, v| "#{k}=#{v}" }
      result = entries.map(&.to_unsafe)
      result << Pointer(UInt8).null
      result
    end
  end

  # Information about a system user, resolved from passwd.
  struct UserInfo
    getter username : String
    getter uid : LibC::UidT
    getter gid : LibC::GidT
    getter home : String?
    getter shell : String?

    def initialize(@username : String, @uid, @gid, @home : String?, @shell : String?)
    end

    # Look up a user by username from the system passwd database.
    def self.lookup(username : String) : UserInfo?
      pwd = LibC.getpwnam(username)
      return nil unless pwd

      home = pwd.value.pw_dir.null? ? nil : String.new(pwd.value.pw_dir)
      shell = pwd.value.pw_shell.null? ? nil : String.new(pwd.value.pw_shell)

      new(username, pwd.value.pw_uid, pwd.value.pw_gid, home, shell)
    end
  end
end
