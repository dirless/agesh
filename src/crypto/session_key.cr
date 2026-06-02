require "age-crystal"

module AgeSh
  module Crypto
    # Derive the transport key from an X25519 shared secret.
    #
    # Both sides call this with the same inputs (they derive the same shared secret
    # via DH, and use the same salt = concat of both ephemeral public keys).
    module SessionKey
      # Derive a transport key from the X25519 shared secret and the
      # concatenated ephemeral public keys (client_pub + server_pub).
      def self.derive(shared_secret : Bytes, client_pub : Bytes, server_pub : Bytes) : Bytes
        raise Error.new("Shared secret must be 32 bytes") unless shared_secret.size == 32
        raise Error.new("Client pubkey must be 32 bytes") unless client_pub.size == 32
        raise Error.new("Server pubkey must be 32 bytes") unless server_pub.size == 32

        salt = Bytes.new(64)
        client_pub.copy_to(salt[0, 32])
        server_pub.copy_to(salt[32, 32])

        Age::HKDF.sha256(shared_secret, salt, Constants::TRANSPORT_INFO.to_slice, 32)
      end
    end
  end
end
