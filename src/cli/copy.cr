require "../agesh"
require "socket"

module AgeSh
  module CopyCLI
    def self.run(args : Array(String)) : Nil
      if args.empty?
        STDERR.puts "age-cp v#{Constants::VERSION}"
        print_help
        return
      end

      # Only treat -v/-h as age-cp's own flags when they lead the command line.
      # Mid-command they belong to the wrapped rsync (e.g. -h = human-readable,
      # -v = verbose) and must be forwarded, not intercepted.
      case args[0]
      when "-v", "--version"
        STDERR.puts "age-cp v#{Constants::VERSION}"
        return
      when "-h", "--help"
        print_help
        return
      end

      # --debug turns on verbose logging. Strip it from the args so it isn't
      # forwarded to rsync; direct mode re-adds it to the --rsh command so the
      # tunnel child (which prints the handshake/auth logs) is verbose too.
      debug = args.includes?("--debug")
      Logger.level = Logger::DEBUG if debug
      args = args.reject("--debug")

      # Mode detection:
      # 1. Explicit tunnel: flags -- command   (age-cp [flags] host -- rsync ...)
      # 2. SSH-style tunnel: flags host command (used by rsync --rsh, no --)
      # 3. Direct mode: src dest               (wraps rsync locally)
      if dash_idx = args.index("--")
        run_tunnel(args[0...dash_idx], args[dash_idx + 1..])
      else
        flags, host, command = parse_rsh_args(args)
        # Distinguish rsync's --rsh invocation (age-cp host rsync --server ... path)
        # from a user's direct copy (age-cp src... user@host:dest). In a direct copy
        # the LAST operand is a remote spec containing ':'; rsync's remote command
        # ends in a local-style path with no ':'.
        last_operand = command.empty? ? host : command.last
        if !host.empty? && !command.empty? && !last_operand.includes?(':')
          run_tunnel(flags + [host], command)
        else
          run_direct(args, debug)
        end
      end
    end

    # Tunnel mode: connect, auth, exec remote command, proxy stdin/stdout.
    # This is the --rsh replacement mode used by rsync.
    private def self.run_tunnel(flags : Array(String), command : Array(String)) : Nil
      host, port, username, identity = parse_tunnel_args(flags)

      # Load identity
      identity_path = File.expand_path(identity)
      unless File.exists?(identity_path)
        STDERR.puts "Error: identity file not found: #{identity_path}"
        LibC.exit(1)
      end
      secret_key_str = begin
        lines = File.read_lines(identity_path)
        lines.find { |l| l.starts_with?("AGE-SECRET-KEY-") } || raise "no secret key found"
      end
      begin
        Age::SecretKey.new(secret_key_str)
      rescue ex : Age::Error
        STDERR.puts "Error: invalid identity file #{identity_path}: #{ex.message}"
        LibC.exit(1)
      end

      hrp, sec_bytes = Age::Bech32.decode(secret_key_str.downcase)
      raise Error.new("Invalid identity key HRP") unless hrp == "age-secret-key-"
      pub_bytes = Age::X25519.public_from_private(sec_bytes)
      pubkey = Age::PublicKey.new(Age::Bech32.encode("age", pub_bytes))

      full_command = command.join(" ")

      socket : TCPSocket? = nil
      begin
        # Connect
        socket = TCPSocket.new(host, port)

        # Ignore SIGPIPE — prevents broken-pipe signals during socket writes
        LibC.signal(LibC::SIGPIPE, LibC::SIG_IGN)

        # Phase 1: Handshake
        _server_pub, transport = Handshake.client(socket)

        # Phase 2: Authenticate
        Authentication.client(transport, socket, username, pubkey.value, sec_bytes, pub_bytes)

        # Phase 3: Exec setup
        Session.client_exec_setup(transport, socket, full_command)

        # Phase 4: Proxy stdin/stdout (no terminal raw mode)
        exit_code = tunnel_proxy(transport, socket)

        LibC.exit(exit_code)
      rescue ex : AgeSh::Error
        STDERR.puts "Error: #{ex.message}"
        LibC.exit(1)
      rescue ex : Socket::Error
        STDERR.puts "Error: #{ex.message}"
        LibC.exit(1)
      ensure
        socket.try(&.close) rescue nil
      end
    end

    # Direct mode: check rsync, exec rsync with age-cp as --rsh.
    private def self.run_direct(args : Array(String), debug : Bool) : Nil
      username = ENV["USER"]? || begin
        STDERR.puts "Error: cannot determine username (USER not set); specify user@host explicitly"
        LibC.exit(1)
      end
      port = Constants::DEFAULT_PORT
      identity = File.expand_path(Constants::DEFAULT_IDENTITY_FILE, home: true)
      positional = [] of String
      progress = false
      # Flags age-cp doesn't recognize are passed straight through to rsync,
      # so e.g. `-P`, `--progress`, or `--bwlimit=1M` work as expected.
      rsync_flags = [] of String

      i = 0
      while i < args.size
        arg = args[i]
        case arg
        when "-l"
          i += 1
          username = args[i]? || username if i < args.size
        when "-p"
          i += 1
          port = args[i]?.to_s.to_i? || port if i < args.size
        when "-i"
          i += 1
          identity = args[i]? || identity if i < args.size
        when "--progress"
          # age-cp convenience: a single overall, human-readable progress bar
          # (expands to rsync's --info=progress2 -h) so you don't have to know
          # rsync's native switches.
          progress = true
        else
          if arg.starts_with?('-')
            rsync_flags << arg
          else
            positional << arg
          end
        end
        i += 1
      end

      if progress
        rsync_flags << "--info=progress2"
        rsync_flags << "-h"
      end

      # Require exactly one source and one destination. Refusing extra operands
      # catches typos (e.g. a stray valid filename) instead of silently copying
      # something the user didn't intend.
      if positional.size < 2
        STDERR.puts "Error: source and destination required"
        STDERR.puts "Usage: age-cp [options] source [user@]host:dest"
        LibC.exit(1)
      elsif positional.size > 2
        STDERR.puts "Error: too many arguments (#{positional.size}); expected one source and one destination"
        STDERR.puts "Usage: age-cp [options] source [user@]host:dest"
        LibC.exit(1)
      end

      source = positional[0]
      dest_spec = positional[1]

      # Parse [user@]host:path — split on first '@' then first ':'
      if at_idx = dest_spec.index('@')
        username = dest_spec[0...at_idx]
        dest_spec = dest_spec[at_idx + 1..]
      end
      colon_idx = dest_spec.index(':')
      unless colon_idx
        STDERR.puts "Error: destination must be in [user@]host:path format"
        LibC.exit(1)
      end
      host = dest_spec[0...colon_idx]
      remote_path = dest_spec[colon_idx + 1..]

      # There is no remote shell to expand '~', so rewrite it ourselves. The
      # server chdirs to the user's home before exec, so a relative path lands
      # there. '~user' can't be resolved without the remote passwd — warn instead.
      if remote_path == "~"
        remote_path = "."
        STDERR.puts "Note: '~' isn't expanded by a remote shell; targeting the home directory."
      elsif remote_path.starts_with?("~/")
        remote_path = remote_path[2..]
        STDERR.puts "Note: '~/' isn't expanded by a remote shell; resolving '#{remote_path}' relative to the home directory."
      elsif remote_path.starts_with?('~')
        STDERR.puts "Warning: '~user' paths aren't expanded (no remote shell); use an absolute path if this fails."
      end

      # Check rsync is available locally
      unless ExecSession.command_exists?("rsync")
        STDERR.puts "Error: rsync is not installed. Install it with your package manager."
        LibC.exit(1)
      end

      # Resolve age-cp's own path for the --rsh argument
      age_cp_path = Process.executable_path || "age-cp"

      # Build rsync command. Any pass-through flags (e.g. --progress) go before
      # the --rsh argument and the file operands.
      rsh_arg = "#{age_cp_path} -l #{username} -p #{port} -i #{identity}"
      rsh_arg += " --debug" if debug
      rsync_argv = ["rsync", "-az"]
      rsync_argv.concat(rsync_flags)
      rsync_argv << "--rsh=#{rsh_arg}"
      rsync_argv << source
      rsync_argv << "#{username}@#{host}:#{remote_path}"

      # Hand off to rsync
      c_argv = rsync_argv.map(&.to_unsafe)
      c_argv << Pointer(UInt8).null
      LibC.execvp("rsync", c_argv.to_unsafe)
      # If execvp fails
      STDERR.puts "Error: failed to exec rsync"
      LibC.exit(127)
    end

    # Proxy stdin/stdout through the encrypted channel.
    # Returns the remote exit code (0 on success).
    #
    # Fiber 1 sends stdin to the server then sends TAG_SESSION_END on EOF.
    # Fiber 2 reads server output until it receives TAG_EXIT_CODE or EOF, then
    # reports the final exit code. The main fiber blocks on that single code,
    # so it can never hang waiting for a code the server didn't send.
    private def self.tunnel_proxy(
      transport : Transport::Session,
      socket : TCPSocket,
    ) : Int32
      result_ch = Channel(Int32).new(1)

      stdin_io = IO::FileDescriptor.new(0)
      stdout_io = IO::FileDescriptor.new(1)

      # Fiber 1: stdin -> socket. Sends TAG_SESSION_END on EOF.
      spawn do
        buf = Bytes.new(Constants::MAX_PAYLOAD_SIZE)
        loop do
          count = stdin_io.read(buf)
          if count == 0
            send_end(transport, socket)
            break
          end
          payload = buf[0, count]
          encrypted = transport.send_record(Constants::TAG_DATA, payload)
          Framer.write_record(socket, encrypted)
        end
      rescue ex
        send_end(transport, socket) rescue nil
      end

      # Fiber 2: socket -> stdout. Always reports exactly one exit code so the
      # main fiber can never block — defaults to 0 when the server closes the
      # connection (EOF / TAG_SESSION_END) without an explicit TAG_EXIT_CODE.
      spawn do
        code = 0
        loop do
          begin
            result = read_tunnel_record(transport, socket, stdout_io)
            case result
            when Int32
              code = result
              break
            when false
              break
            end
          rescue ex : IO::Error
            break
          end
        end
        result_ch.send(code)
      end

      # Block until Fiber 2 reports the final exit code.
      code = result_ch.receive
      Logger.debug("Tunnel proxy ended")
      code
    end

    # Read a record from the socket in tunnel mode.
    # Returns true for data, Int32 for exit code, false for session end.
    private def self.read_tunnel_record(transport, socket : IO, stdout : IO::FileDescriptor) : Bool | Int32
      len_buf = Bytes.new(4)
      return false unless Framer.read_exact(socket, len_buf)
      length = IO::ByteFormat::BigEndian.decode(UInt32, len_buf)
      return false if length == 0 || length > Constants::MAX_RECORD_SIZE

      record = Bytes.new(length)
      return false unless Framer.read_exact(socket, record)

      tag, payload = transport.recv_record(record)

      case tag
      when Constants::TAG_DATA
        stdout.write(payload)
        stdout.flush
        true
      when Constants::TAG_STDERR
        # Remote stderr — forward to our stderr, kept off the protocol stream.
        STDERR.write(payload)
        STDERR.flush
        true
      when Constants::TAG_EXIT_CODE
        code = (payload[0]? || 0_u8).to_i
        Logger.debug("Remote exit code: #{code}")
        code
      when Constants::TAG_SESSION_END
        false
      else
        Logger.warn("Unknown data channel tag: #{tag}")
        true
      end
    end

    private def self.send_end(transport, socket : IO) : Nil
      encrypted = transport.send_record(Constants::TAG_SESSION_END, Bytes.new(0))
      Framer.write_record(socket, encrypted) rescue nil
    end

    # Parse tunnel-mode arguments: -l user, -p port, -i identity, host
    private def self.parse_tunnel_args(args : Array(String)) : {String, Int32, String, String}
      user = ENV["USER"]? || ""
      port = Constants::DEFAULT_PORT
      identity = File.expand_path(Constants::DEFAULT_IDENTITY_FILE, home: true)
      host = ""

      i = 0
      while i < args.size
        arg = args[i]
        case arg
        when "-l"
          i += 1
          user = args[i]? || user if i < args.size
        when "-p"
          i += 1
          port = args[i]?.to_s.to_i? || Constants::DEFAULT_PORT if i < args.size
        when "-i"
          i += 1
          identity = args[i]? || identity if i < args.size
        else
          # Last non-flag arg is the host (may include user@)
          if arg.includes?('@')
            at_idx = arg.index('@').not_nil!
            user = arg[0...at_idx]
            host = arg[at_idx + 1..]
          elsif !arg.starts_with?('-')
            host = arg
          end
        end
        i += 1
      end

      if user.empty?
        STDERR.puts "Error: cannot determine username (USER not set; use -l user)"
        LibC.exit(1)
      end
      if host.empty?
        STDERR.puts "Error: no host specified (use user@host or -l user host)"
        LibC.exit(1)
      end

      {host, port, user, identity}
    end

    # Parse SSH-style args: [flags] host [command...].
    # Only -l/-p/-i (with their values) are consumed as age-cp flags.
    # Parsing STOPS at the first non-flag argument (the host).
    # Everything after the host is the remote command (and may start with '-').
    private def self.parse_rsh_args(args : Array(String)) : {Array(String), String, Array(String)}
      flags = [] of String
      host = ""
      command = [] of String
      i = 0
      while i < args.size
        arg = args[i]
        if host.empty?
          if arg == "-l" || arg == "-p" || arg == "-i"
            flags << arg
            i += 1
            flags << args[i] if i < args.size
          elsif arg.starts_with?("-")
            flags << arg
          else
            host = arg
          end
        else
          command << arg
        end
        i += 1
      end
      {flags, host, command}
    end

    private def self.print_help : Nil
      STDERR.puts <<-HELP
        age-cp - AGE-encrypted file copy (rsync over agesh)

        Usage:
          age-cp source user@host:dest          Direct mode (wraps rsync)
          age-cp [options] user@host -- command  Tunnel mode (--rsh for rsync)

        Tunnel mode is used internally by rsync via --rsh.
        Direct mode checks rsync is available on both sides.

        Options:
          -l, --login USER   Remote username (default: $USER)
          -p, --port PORT    Server port (default: #{Constants::DEFAULT_PORT})
          -i, --identity     Identity file (default: ~/.age/identity)
          --progress         Show a transfer progress bar
          --debug            Verbose connection logging
          -v, --version      Show version
          -h, --help         Show this help

        Any other flags are passed straight through to rsync (e.g. -P,
        --bwlimit=1M). Note: -v/-h are age-cp's own only as the first argument;
        elsewhere they go to rsync (verbose / human-readable).

        Remote paths:
          Commands run without a remote shell, so '~' is NOT expanded. Direct
          mode rewrites a leading '~/' to a home-relative path automatically;
          for the --rsh form, use an absolute path or one relative to the home
          directory (e.g. host:dir instead of host:~/dir).

        Examples:
          age-cp ./src user@host:/tmp/dest
          age-cp ./src user@host:dir          # lands in the home directory

          # Drive rsync yourself (verbose/progress, custom flags):
          rsync -avz --progress \\
            --rsh="age-cp -l user -p #{Constants::DEFAULT_PORT} -i /path/to/identity" \\
            ./src user@host:dir
      HELP
    end
  end
end

AgeSh::CopyCLI.run(ARGV)
