require "age-crystal"

module AgeSh
  # Handles the initial version exchange and X25519 key exchange.
  # After this, both sides have a Transport::Session ready for encrypted communication.
  module Handshake
    # Perform the client-side handshake. Returns {server_ephemeral_pub, transport_session}.
    def self.client(io : IO) : {Bytes, Transport::Session}
      # Send version
      Framer.write_message(io, Messages.write_version)

      # Read server version ack
      data = Framer.read_message(io)
      version, _ = Messages.read_version(data)
      raise Error.new("Unsupported server version: #{version}") unless version == Constants::PROTOCOL_VERSION

      # Generate ephemeral keypair
      ephem_priv, ephem_pub = Age::X25519.generate_keypair

      # Send our ephemeral public key
      Framer.write_message(io, Messages.write_key_exchange(ephem_pub))

      # Read server's ephemeral public key
      data = Framer.read_message(io)
      server_pub = Messages.read_key_exchange(data)

      # Derive shared secret and transport key
      shared_secret = Age::X25519.shared_secret(ephem_priv, server_pub)
      transport_key = Crypto::SessionKey.derive(shared_secret, ephem_pub, server_pub)
      transport_session = Transport::Session.new(transport_key, Transport::Role::Client)

      Logger.debug("Client handshake complete")

      {server_pub, transport_session}
    end

    # Perform the server-side handshake. Returns {client_ephemeral_pub, transport_session}.
    def self.server(io : IO) : {Bytes, Transport::Session}
      # Read client version
      data = Framer.read_message(io)
      version, _ = Messages.read_version(data)
      raise Error.new("Unsupported client version: #{version}") unless version == Constants::PROTOCOL_VERSION

      # Send version ack
      Framer.write_message(io, Messages.write_version)

      # Generate ephemeral keypair
      ephem_priv, ephem_pub = Age::X25519.generate_keypair

      # Read client's ephemeral public key
      data = Framer.read_message(io)
      client_pub = Messages.read_key_exchange(data)

      # Send our ephemeral public key
      Framer.write_message(io, Messages.write_key_exchange(ephem_pub))

      # Derive shared secret and transport key
      shared_secret = Age::X25519.shared_secret(ephem_priv, client_pub)
      transport_key = Crypto::SessionKey.derive(shared_secret, client_pub, ephem_pub)
      transport_session = Transport::Session.new(transport_key, Transport::Role::Server)

      Logger.debug("Server handshake complete")

      {client_pub, transport_session}
    end
  end
end
