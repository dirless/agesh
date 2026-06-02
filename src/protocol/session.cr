module AgeSh
  # Session setup and encrypted data channel.
  #
  # After authentication, the client sends terminal parameters and environment.
  # The server allocates a PTY and confirms readiness. After that, raw encrypted
  # data flows bidirectionally (no more framing).
  module Session
    # Client sends session setup parameters.
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
      Messages.read_session_ready(ready_data) || raise Error.new("Session setup failed")

      Logger.debug("Session setup complete")
    end

    # Server reads session setup and confirms readiness.
    # Returns {term_type, rows, cols, env}.
    def self.server_setup(transport : Transport::Session, io : IO) : {String, UInt32, UInt32, Hash(String, String)}
      encrypted_setup = Framer.read_message(io)
      _, setup_data = transport.recv_record(encrypted_setup)
      term_type, rows, cols, env = Messages.read_session_setup(setup_data)

      Logger.debug("Session request: term=#{term_type} #{rows}x#{cols} env=#{env.size} vars")

      # Confirm readiness
      ready = Messages.write_session_ready
      encrypted_ready = transport.send_record(Constants::TAG_DATA, ready)
      Framer.write_message(io, encrypted_ready)

      {term_type, rows, cols, env}
    end
  end
end
