module AgeSh
  module Server
    # Handles a single client connection through the full protocol:
    # handshake -> auth -> session setup -> data channel proxy.
    class Connection
      def initialize(@socket : TCPSocket, @config : Config)
      end

      def run : Nil
        begin
          # Phase 1: Handshake
          client_pub, transport = Handshake.server(@socket)

          # Phase 2: Authentication
          key_resolver = Proc(String, String?).new do |uname|
            info = UserInfo.lookup(uname)
            next nil unless info
            if home = info.home
              File.join(home, Constants::AUTHORIZED_KEYS_DIR, Constants::AUTHORIZED_KEYS_FILE)
            end
          end
          username = Authentication.server(transport, @socket, key_resolver)

          # Look up the user
          user_info = UserInfo.lookup(username)
          raise Error.new("User #{username} not found") unless user_info

          # Phase 3: Session setup
          term_type, rows, cols, env = Session.server_setup(transport, @socket)

          # Phase 4: Allocate PTY and spawn shell
          master_fd, slave_path = PTY.allocate
          begin
            child_pid = UserSession.spawn_with_master(
              master_fd, slave_path, user_info, term_type, rows, cols, env
            )
          rescue ex
            LibC.close(master_fd) rescue nil
            raise ex
          end

          Logger.info("Session started: user=#{username} pid=#{child_pid} term=#{term_type} #{rows}x#{cols}")

          # Phase 5: Two-fiber proxy loop
          pty_io = IO::FileDescriptor.new(master_fd)
          proxy(transport, @socket, pty_io, master_fd, child_pid)
        rescue ex : Exception
          Logger.error("Connection error: #{ex.message}")
        ensure
          @socket.close rescue nil
        end
      end

      # Two-fiber proxy: one reads PTY and writes socket, one reads socket and writes PTY.
      private def proxy(
        transport : Transport::Session,
        socket : TCPSocket,
        pty_io : IO::FileDescriptor,
        master_fd : Int32,
        child_pid : Int32,
      ) : Nil
        done = Channel(Nil).new(2)

        # Fiber 1: PTY -> Socket (shell output)
        spawn do
          buf = Bytes.new(Constants::MAX_RECORD_SIZE)
          loop do
            count = pty_io.read(buf)
            if count == 0
              done.send(nil) rescue nil
              break
            end
            payload = buf[0, count]
            encrypted = transport.send_record(Constants::TAG_DATA, payload)
            Framer.write_record(socket, encrypted)
          end
        rescue ex
          Logger.debug("PTY->Socket fiber error: #{ex.message}")
          done.send(nil) rescue nil
        end

        # Fiber 2: Socket -> PTY (client input)
        spawn do
          loop do
            begin
              if !read_socket_record(transport, socket, master_fd)
                done.send(nil) rescue nil
                break
              end
            rescue ex : IO::Error
              done.send(nil) rescue nil
              break
            end
          end
        end

        # Block until one direction signals done
        done.receive
        Logger.debug("Proxy loop ended")
      ensure
        LibC.close(master_fd) rescue nil
        UserSession.wait(child_pid) rescue nil
      end

      private def read_socket_record(transport, io : IO, master_fd : Int32) : Bool
        len_buf = Bytes.new(4)
        return false unless Framer.read_exact(io, len_buf)
        length = IO::ByteFormat::BigEndian.decode(UInt32, len_buf)
        return false if length == 0 || length > Constants::MAX_RECORD_SIZE

        record = Bytes.new(length)
        return false unless Framer.read_exact(io, record)

        tag, payload = transport.recv_record(record)

        case tag
        when Constants::TAG_DATA
          # Write full payload to PTY master, handling partial writes
          offset = 0
          while offset < payload.size
            written = LibC.write(master_fd, payload.to_unsafe.as(Void*).offset(offset), payload.size - offset)
            return false if written < 0
            offset += written
          end
        when Constants::TAG_WINDOW_RESIZE
          handle_resize(payload, master_fd)
        when Constants::TAG_SESSION_END
          return false
        else
          Logger.warn("Unknown data channel tag: #{tag}")
        end
        true
      end

      private def handle_resize(payload : Bytes, master_fd : Int32) : Nil
        raise Error.new("Resize payload too small") if payload.size < 8
        rows = IO::ByteFormat::BigEndian.decode(UInt32, payload[0, 4])
        cols = IO::ByteFormat::BigEndian.decode(UInt32, payload[4, 4])
        PTY.set_winsize(master_fd, rows, cols)
        Logger.debug("Window resize: #{rows}x#{cols}")
      end
    end
  end
end
