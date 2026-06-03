module AgeSh
  # Session setup and encrypted data channel.
  #
  # After authentication, the client sends terminal parameters and environment.
  # The server allocates a PTY and confirms readiness. After that, raw encrypted
  # data flows bidirectionally (no more framing).
  module Session
    # Client sends session setup parameters (interactive shell mode).
    def self.client_setup(
      transport : Transport::Session,
      io : IO,
      term_type : String,
      rows : UInt32,
      cols : UInt32,
      env : Hash(String, String) = {} of String => String,
    ) : Nil
      setup = Messages.write_session_setup(term_type, rows, cols, env)
      encrypted = transport.send_record(Constants::TAG_DATA, setup)
      Framer.write_message(io, encrypted)

      # Read session ready
      encrypted_ready = Framer.read_message(io)
      _, ready_data = transport.recv_record(encrypted_ready)
      success, message = Messages.read_session_ready(ready_data)
      success || raise Error.new("Session setup failed: #{message}")

      Logger.debug("Session setup complete")
    end

    # Server reads session setup and confirms readiness (interactive shell mode).
    # Returns {term_type, rows, cols, env}.
    def self.server_setup(transport : Transport::Session, io : IO) : {String, UInt32, UInt32, Hash(String, String)}
      encrypted_setup = Framer.read_message(io)
      _, setup_data = transport.recv_record(encrypted_setup)
      term_type, rows, cols, env = Messages.read_session_setup(setup_data)

      Logger.debug("Session request: term=#{term_type} #{rows}x#{cols} env=#{env.size} vars")

      # Confirm readiness
      ready = Messages.write_session_ready(true)
      encrypted_ready = transport.send_record(Constants::TAG_DATA, ready)
      Framer.write_message(io, encrypted_ready)

      {term_type, rows, cols, env}
    end

    # Client sends exec setup parameters (command mode, no PTY).
    def self.client_exec_setup(
      transport : Transport::Session,
      io : IO,
      command : String,
      env : Hash(String, String) = {} of String => String,
    ) : Nil
      setup = Messages.write_exec_setup(command, env)
      encrypted = transport.send_record(Constants::TAG_DATA, setup)
      Framer.write_message(io, encrypted)

      # Read session ready (may contain error if command check failed)
      encrypted_ready = Framer.read_message(io)
      _, ready_data = transport.recv_record(encrypted_ready)
      success, message = Messages.read_session_ready(ready_data)
      success || raise Error.new("Exec setup failed: #{message}")

      Logger.debug("Exec session setup complete")
    end

    # Server reads exec setup and confirms readiness (command mode, no PTY).
    # Returns {command, env}.
    def self.server_exec_setup(transport : Transport::Session, io : IO) : {String, Hash(String, String)}
      encrypted_setup = Framer.read_message(io)
      _, setup_data = transport.recv_record(encrypted_setup)
      command, env = Messages.read_exec_setup(setup_data)

      Logger.debug("Exec request: command=#{command} env=#{env.size} vars")

      # Confirm readiness
      ready = Messages.write_session_ready(true)
      encrypted_ready = transport.send_record(Constants::TAG_DATA, ready)
      Framer.write_message(io, encrypted_ready)

      {command, env}
    end
  end
end
