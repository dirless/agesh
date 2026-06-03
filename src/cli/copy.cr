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

      if args.includes?("-v") || args.includes?("--version")
        STDERR.puts "age-cp v#{Constants::VERSION}"
        return
      end

      if args.includes?("-h") || args.includes?("--help")
        print_help
        return
      end

      # Mode detection:
      # 1. Explicit tunnel: flags -- command   (age-cp [flags] host -- rsync ...)
      # 2. SSH-style tunnel: flags host command (used by rsync --rsh, no --)
      # 3. Direct mode: src dest               (wraps rsync locally)
      if dash_idx = args.index("--")
        run_tunnel(args[0...dash_idx], args[dash_idx + 1..])
      else
        flags, host, command = parse_rsh_args(args)
        if !host.empty? && !command.empty?
          run_tunnel(flags + [host], command)
        else
          run_direct(args)
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

      # Connect
      socket = TCPSocket.new(host, port)

      begin
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
        socket.close rescue nil
      end
    end

    # Direct mode: check rsync, exec rsync with age-cp as --rsh.
    private def self.run_direct(args : Array(String)) : Nil
      # Parse source and destination
      if args.size < 2
        STDERR.puts "Error: source and destination required"
        STDERR.puts "Usage: age-cp source [user@host:]dest"
        LibC.exit(1)
      end

      source = args[0]
      dest = args[1]

      # Extract user/host from destination if specified
      username = ENV["USER"]? || begin
        STDERR.puts "Error: cannot determine username (USER not set); specify user@host explicitly"
        LibC.exit(1)
      end
      port = Constants::DEFAULT_PORT
      identity = File.expand_path(Constants::DEFAULT_IDENTITY_FILE, home: true)

      if idx = dest.index('@')
        username = dest[0...idx]
        dest = dest[idx + 1..]
      end
      if host_idx = dest.rindex(':')
        port = dest[host_idx + 1..].to_i? || port
        dest = dest[0...host_idx]
      end

      # Check rsync is available locally
      unless ExecSession.command_exists?("rsync")
        STDERR.puts "Error: rsync is not installed. Install it with your package manager."
        LibC.exit(1)
      end

      # Resolve age-cp's own path for the --rsh argument
      age_cp_path = Process.executable_path || "age-cp"

      # Build rsync command
      rsh_arg = "#{age_cp_path} -l #{username} -p #{port} -i #{identity}"
      rsync_argv = [
        "rsync", "-az",
        "--rsh=#{rsh_arg}",
        source, "#{username}@#{dest}:#{dest}",
      ]

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
    # Fiber 1 sends stdin to the server then sends TAG_SESSION_END (no done signal).
    # Fiber 2 reads server output until it receives TAG_EXIT_CODE or EOF, then signals done.
    # This ensures we receive all output before exiting.
    private def self.tunnel_proxy(
      transport : Transport::Session,
      socket : TCPSocket,
    ) : Int32
      done = Channel(Nil).new(1)
      exit_code = Channel(Int32).new(1)

      stdin_io = IO::FileDescriptor.new(0)
      stdout_io = IO::FileDescriptor.new(1)

      # Fiber 1: stdin -> socket. Sends TAG_SESSION_END on EOF. Does NOT signal done.
      spawn do
        buf = Bytes.new(Constants::MAX_RECORD_SIZE)
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

      # Fiber 2: socket -> stdout. Signals done when server closes or sends exit code.
      spawn do
        loop do
          begin
            result = read_tunnel_record(transport, socket, stdout_io)
            case result
            when Int32
              exit_code.send(result)
              done.send(nil) rescue nil
              break
            when false
              done.send(nil) rescue nil
              break
            end
          rescue ex : IO::Error
            done.send(nil) rescue nil
            break
          end
        end
      end

      # Block until server closes (Fiber 2 signals done).
      done.receive
      Logger.debug("Tunnel proxy ended")
      exit_code.receive? || 0
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
          -v, --version      Show version
          -h, --help         Show this help

        Examples:
          age-cp ./src user@host:/tmp/dest
          rsync -avz --rsh="age-cp -l user" ./src user@host:/tmp/dest
      HELP
    end
  end
end

AgeSh::CopyCLI.run(ARGV)
