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

          # Phase 3: Read next message to determine session type
          encrypted_setup = Framer.read_message(@socket)
          _, setup_data = transport.recv_record(encrypted_setup)

          msg_type = setup_data[0]?

          case msg_type
          when Constants::MSG_SESSION_SETUP
            handle_shell_session(transport, user_info, username, setup_data)
          when Constants::MSG_EXEC_SETUP
            handle_exec_session(transport, user_info, username, setup_data)
          else
            raise Error.new("Unknown session setup type: #{msg_type ? "0x#{msg_type.to_s(16)}" : "empty"}")
          end
        rescue ex : Exception
          Logger.error("Connection error: #{ex.message}")
        ensure
          @socket.close rescue nil
        end
      end

      # Interactive shell session: PTY + forked shell.
      private def handle_shell_session(
        transport : Transport::Session,
        user_info : UserInfo,
        username : String,
        setup_data : Bytes,
      ) : Nil
        term_type, rows, cols, env = Messages.read_session_setup(setup_data)

        # Confirm readiness
        ready = Messages.write_session_ready(true)
        encrypted_ready = transport.send_record(Constants::TAG_DATA, ready)
        Framer.write_message(@socket, encrypted_ready)

        # Allocate PTY and spawn shell
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

        pty_io = IO::FileDescriptor.new(master_fd)
        proxy(transport, @socket, pty_io, master_fd, child_pid)
      end

      # Command execution session: pipes + exec (no PTY).
      private def handle_exec_session(
        transport : Transport::Session,
        user_info : UserInfo,
        username : String,
        setup_data : Bytes,
      ) : Nil
        command, env = Messages.read_exec_setup(setup_data)

        # Check if the command exists before replying
        cmd_name = command.split(' ', 2)[0]?
        if cmd_name && !ExecSession.command_exists?(cmd_name)
          ready = Messages.write_session_ready(false, "#{cmd_name}: command not found")
          encrypted_ready = transport.send_record(Constants::TAG_DATA, ready)
          Framer.write_message(@socket, encrypted_ready)
          Logger.info("Exec rejected: #{cmd_name} not found for user=#{username}")
          return
        end

        # Confirm readiness
        ready = Messages.write_session_ready(true)
        encrypted_ready = transport.send_record(Constants::TAG_DATA, ready)
        Framer.write_message(@socket, encrypted_ready)

        exec_result = ExecSession.spawn_with_pipes(command, user_info, env)
        Logger.info("Exec started: user=#{username} pid=#{exec_result.child_pid} cmd=#{command}")

        exec_proxy(transport, @socket, exec_result)
      end

      # Two-fiber proxy for PTY sessions.
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

      # Two-fiber proxy for exec sessions (pipes, no PTY, no window resize).
      # Sends TAG_EXIT_CODE before closing so the client can propagate the exit status.
      #
      # Flow: Fiber 2 closes child stdin when the client sends TAG_SESSION_END (EOF),
      # which lets the child finish and close its stdout. Fiber 1 then reads EOF on
      # stdout and signals done. This ensures all output reaches the client before exit.
      private def exec_proxy(
        transport : Transport::Session,
        socket : TCPSocket,
        exec_result : ExecSession::ExecResult,
      ) : Nil
        done = Channel(Nil).new(1)
        stdin_fd = exec_result.stdin_fd

        # Fiber 1: child stdout -> Socket. Signals done when child closes stdout (exits).
        spawn do
          stdout_io = IO::FileDescriptor.new(exec_result.stdout_fd)
          buf = Bytes.new(Constants::MAX_RECORD_SIZE)
          loop do
            count = stdout_io.read(buf)
            if count == 0
              done.send(nil) rescue nil
              break
            end
            payload = buf[0, count]
            encrypted = transport.send_record(Constants::TAG_DATA, payload)
            Framer.write_record(socket, encrypted)
          end
        rescue ex
          Logger.debug("Exec stdout->Socket fiber error: #{ex.message}")
          done.send(nil) rescue nil
        end

        # Fiber 2: Socket -> child stdin.
        # On TAG_SESSION_END or error, closes child stdin so the child gets EOF.
        # Does NOT signal done — Fiber 1 owns the done signal.
        spawn do
          loop do
            begin
              if !read_exec_socket_record(transport, socket, stdin_fd)
                LibC.close(stdin_fd) rescue nil
                break
              end
            rescue ex : IO::Error
              LibC.close(stdin_fd) rescue nil
              break
            end
          end
        end

        # Block until child stdout is exhausted (Fiber 1 signals done).
        done.receive
        Logger.debug("Exec proxy loop ended")
      ensure
        LibC.close(exec_result.stdout_fd) rescue nil
        status = UserSession.wait(exec_result.child_pid) rescue nil
        if status
          code = UserSession.exit_code(status)
          Logger.debug("Exec exited with code #{code}")
          payload = Bytes.new(1)
          payload[0] = code.to_u8
          encrypted = transport.send_record(Constants::TAG_EXIT_CODE, payload)
          Framer.write_record(socket, encrypted) rescue nil
        end
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
            written = LibC.write(master_fd, payload[offset..].to_unsafe.as(Void*), payload.size - offset)
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

      private def read_exec_socket_record(transport, io : IO, stdin_fd : Int32) : Bool
        len_buf = Bytes.new(4)
        return false unless Framer.read_exact(io, len_buf)
        length = IO::ByteFormat::BigEndian.decode(UInt32, len_buf)
        return false if length == 0 || length > Constants::MAX_RECORD_SIZE

        record = Bytes.new(length)
        return false unless Framer.read_exact(io, record)

        tag, payload = transport.recv_record(record)

        case tag
        when Constants::TAG_DATA
          # Write full payload to child stdin, handling partial writes
          offset = 0
          while offset < payload.size
            written = LibC.write(stdin_fd, payload[offset..].to_unsafe.as(Void*), payload.size - offset)
            return false if written < 0
            offset += written
          end
        when Constants::TAG_SESSION_END
          return false
        else
          Logger.warn("Unknown data channel tag in exec mode: #{tag}")
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
