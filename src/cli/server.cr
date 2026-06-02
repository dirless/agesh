require "../agesh"
require "socket"

module AgeSh
  module ServerCLI
    def self.run(args : Array(String)) : Nil
      if args.empty?
        puts "agesh-server v#{Constants::VERSION}"
        print_help
        return
      end

      if args.includes?("-v") || args.includes?("--version")
        puts "agesh-server v#{Constants::VERSION}"
        return
      end

      config = parse_args(args)

      Logger.info("agesh-server v#{Constants::VERSION} starting on #{config.bind_address}:#{config.port}")

      server = TCPServer.new(config.bind_address, config.port)

      # Ignore SIGPIPE globally — prevents broken-pipe signals during socket writes.
      LibC.signal(LibC::SIGPIPE, LibC::SIG_IGN)

      Logger.info("Listening on #{config.bind_address}:#{config.port}")

      loop do
        client = server.accept
        client_addr = client.remote_address
        Logger.info("New connection from #{client_addr}")

        spawn do
          conn = AgeSh::Server::Connection.new(client, config)
          conn.run
          Logger.info("Connection closed from #{client_addr}")
        rescue ex
          Logger.error("Connection handler error: #{ex.message}")
          client.close rescue nil
        end
      end
    end

    private def self.parse_args(args : Array(String)) : Server::Config
      bind = "0.0.0.0"
      port = Constants::DEFAULT_PORT

      i = 0
      while i < args.size
        case args[i]
        when "-b", "--bind"
          i += 1
          bind = args[i] if i < args.size
        when "-p", "--port"
          i += 1
          port = args[i].to_i? || Constants::DEFAULT_PORT if i < args.size
        when "-h", "--help"
          print_help
          LibC.exit(0)
        when "-v", "--version"
          # handled above
        else
          STDERR.puts "Unknown option: #{args[i]}"
          print_help
          LibC.exit(1)
        end
        i += 1
      end

      Server::Config.new(bind, port)
    end

    private def self.print_help : Nil
      STDERR.puts <<-HELP
        agesh-server - AGE-encrypted terminal server

        Usage:
          agesh-server [options]

        Options:
          -b, --bind ADDR  Bind address (default: 0.0.0.0)
          -p, --port PORT  Listen port (default: #{Constants::DEFAULT_PORT})
          -v, --version    Show version
          -h, --help       Show this help

        Configuration:
          Users place AGE public keys in ~/.age/authorized_keys
          One age1... key per line, # comments supported
      HELP
    end
  end
end

AgeSh::ServerCLI.run(ARGV)
