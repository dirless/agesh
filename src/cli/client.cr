require "../agesh"
require "socket"

module AgeSh
  module ClientCLI
    def self.run(args : Array(String)) : Nil
      if args.empty?
        puts "agesh v#{Constants::VERSION}"
        print_help
        return
      end

      if args.includes?("-v") || args.includes?("--version")
        puts "agesh v#{Constants::VERSION}"
        return
      end

      if args[0] == "keygen"
        run_keygen(args[1..])
        return
      end

      config = parse_args(args)

      # Load identity
      identity_path = File.expand_path(config.identity_file)
      unless File.exists?(identity_path)
        STDERR.puts "Error: identity file not found: #{identity_path}"
        LibC.exit(1)
      end
      secret_key_str = begin
        lines = File.read_lines(identity_path)
        lines.find { |l| l.starts_with?("AGE-SECRET-KEY-") } || raise "no secret key found"
      end
      begin
        Age::SecretKey.new(secret_key_str) # validates prefix before decoding
      rescue ex : Age::Error
        STDERR.puts "Error: invalid identity file #{identity_path}: #{ex.message}"
        LibC.exit(1)
      end

      # Decode secret key to raw bytes
      hrp, sec_bytes = Age::Bech32.decode(secret_key_str.downcase)
      raise Error.new("Invalid identity key HRP") unless hrp == "age-secret-key-"
      pub_bytes = Age::X25519.public_from_private(sec_bytes)
      pubkey = Age::PublicKey.new(Age::Bech32.encode("age", pub_bytes))

      # Connect
      socket = TCPSocket.new(config.host, config.port)

      begin
        # Phase 1: Handshake
        server_pub, transport = Handshake.client(socket)

        # Phase 2: Authenticate
        Authentication.client(transport, socket, config.username, pubkey.value, sec_bytes, pub_bytes)

        # Phase 3: Session setup
        AgeSh::Client::Terminal.update_winsize
        rows, cols = AgeSh::Client::Terminal.winsize
        term_type = AgeSh::Client::Terminal.term_type
        Session.client_setup(transport, socket, term_type, rows, cols)

        Logger.debug("Session established: term=#{term_type} #{rows}x#{cols}")

        # Phase 4: Data channel proxy — put terminal in raw mode for the session
        stdin_io = IO::FileDescriptor.new(0)
        stdout_io = IO::FileDescriptor.new(1)
        AgeSh::Client::Terminal.raw do
          proxy(transport, socket, stdin_io, stdout_io)
        end
      ensure
        socket.close rescue nil
      end
    end

    # Two-fiber proxy: one reads stdin and writes socket, one reads socket and writes stdout.
    # Uses a channel to signal when either direction hits EOF.
    private def self.proxy(
      transport : Transport::Session,
      socket : TCPSocket,
      stdin : IO::FileDescriptor,
      stdout : IO::FileDescriptor,
    ) : Nil
      done = Channel(Nil).new(2)

      # Fiber 1: stdin -> socket
      spawn do
        buf = Bytes.new(Constants::MAX_RECORD_SIZE)
        loop do
          count = stdin.read(buf)
          if count == 0
            # Stdin closed — send session end
            send_end(transport, socket)
            done.send(nil) rescue nil
            break
          end
          payload = buf[0, count]
          encrypted = transport.send_record(Constants::TAG_DATA, payload)
          Framer.write_record(socket, encrypted)
        end
      end

      # Fiber 2: socket -> stdout
      spawn do
        loop do
          begin
            if !read_socket_record(transport, socket, stdout)
              done.send(nil) rescue nil
              break
            end
          rescue ex : IO::Error
            done.send(nil) rescue nil
            break
          end
        end
      end

      # SIGWINCH -> resize
      Signal::WINCH.trap do
        AgeSh::Client::Terminal.update_winsize
        rows, cols = AgeSh::Client::Terminal.winsize
        send_resize(transport, socket, rows, cols)
      rescue
      end

      # Block until one direction signals done
      done.receive
      Logger.debug("Proxy ended")
    end

    private def self.read_socket_record(transport, socket : IO, stdout : IO::FileDescriptor) : Bool
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
      when Constants::TAG_SESSION_END
        return false
      else
        Logger.warn("Unknown data channel tag: #{tag}")
      end
      true
    end

    private def self.send_resize(transport, socket : IO, rows : UInt32, cols : UInt32) : Nil
      payload = Bytes.new(8)
      IO::ByteFormat::BigEndian.encode(rows, payload[0, 4])
      IO::ByteFormat::BigEndian.encode(cols, payload[4, 4])
      encrypted = transport.send_record(Constants::TAG_WINDOW_RESIZE, payload)
      Framer.write_record(socket, encrypted)
    end

    private def self.send_end(transport, socket : IO) : Nil
      encrypted = transport.send_record(Constants::TAG_SESSION_END, Bytes.new(0))
      Framer.write_record(socket, encrypted) rescue nil
    end

    private def self.parse_args(args : Array(String)) : Client::Config
      host = ""
      port = Constants::DEFAULT_PORT
      identity = File.expand_path(Constants::DEFAULT_IDENTITY_FILE, home: true)
      username = ENV["USER"]? || begin
        STDERR.puts "Error: cannot determine username (USER not set); specify user@host explicitly"
        LibC.exit(1)
      end

      i = 0
      while i < args.size
        arg = args[i]
        if arg.starts_with?("-")
          case arg
          when "-p", "--port"
            i += 1
            port = args[i]?.to_s.to_i? || Constants::DEFAULT_PORT if i < args.size
          when "-i", "--identity"
            i += 1
            identity = args[i]? || identity if i < args.size
          when "-h", "--help"
            print_help
            LibC.exit(0)
          when "-v", "--version"
            # handled above
          else
            STDERR.puts "Unknown option: #{arg}"
            print_help
            LibC.exit(1)
          end
        else
          if idx = arg.index('@')
            username = arg[0...idx]
            host = arg[idx + 1..]
          else
            host = arg
          end
          if host_idx = host.rindex(':')
            port = host[host_idx + 1..].to_i? || port
            host = host[0...host_idx]
          end
        end
        i += 1
      end

      if host.empty?
        STDERR.puts "Error: no host specified"
        print_help
        LibC.exit(1)
      end

      Client::Config.new(host, port, username, identity)
    end

    private def self.run_keygen(args : Array(String)) : Nil
      identity_dir = File.expand_path(Constants::AUTHORIZED_KEYS_DIR, home: true)
      identity_file = File.join(identity_dir, "identity")

      if args.includes?("-f") || args.includes?("--force") || !File.exists?(identity_file)
        Dir.mkdir_p(identity_dir) unless Dir.exists?(identity_dir)

        keypair = Age.keygen

        File.write(identity_file, "#{keypair.secret_key.value}\n")
        File.chmod(identity_file, 0o600)

        pubkey_file = File.join(identity_dir, "identity.pub")
        File.write(pubkey_file, "#{keypair.public_key.value}\n")
        File.chmod(pubkey_file, 0o644)

        puts "Generated AGE identity:"
        puts "  Secret: #{identity_file}"
        puts "  Public: #{pubkey_file}"
        puts ""
        puts "Your public key (add this to the server's ~/.age/authorized_keys):"
        puts "  #{keypair.public_key.value}"
      else
        STDERR.puts "Identity file already exists: #{identity_file}"
        STDERR.puts "Use -f to overwrite."
        LibC.exit(1)
      end
    end

    private def self.print_help : Nil
      STDERR.puts <<-HELP
        agesh - AGE-encrypted terminal client

        Usage:
          agesh [user@host] [options]
          agesh keygen [-f]

        Options:
          -p, --port PORT       Server port (default: #{Constants::DEFAULT_PORT})
          -i, --identity FILE   Identity file (default: ~/.age/identity)
          -v, --version         Show version
          -h, --help            Show this help

        Examples:
          agesh user@host
          agesh user@host -p 2222
          agesh user@host -i ~/.age/work-identity
          agesh keygen
      HELP
    end
  end
end

AgeSh::ClientCLI.run(ARGV)
