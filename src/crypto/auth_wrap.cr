require "age-crystal"

module AgeSh
  module Crypto
    # Wraps and unwraps the authentication challenge using the same
    # X25519 + HKDF + ChaCha20-Poly1305 construction as AGE file encryption.
    #
    # This proves that the client holds the private key corresponding to the
    # public key in authorized_keys, without exposing the secret key.
    module AuthWrap
      # Wrap a challenge for a recipient's AGE public key.
      # Returns {ephemeral_public_key, wrapped_challenge (48 bytes)}.
      def self.wrap(challenge : Bytes, recipient_pub_bytes : Bytes) : {Bytes, Bytes}
        raise Error.new("Challenge must be 32 bytes") unless challenge.size == 32
        raise Error.new("Recipient pubkey must be 32 bytes") unless recipient_pub_bytes.size == 32

        ephem_priv, ephem_pub = Age::X25519.generate_keypair
        shared = Age::X25519.shared_secret(ephem_priv, recipient_pub_bytes)

        salt = Bytes.new(64)
        ephem_pub.copy_to(salt[0, 32])
        recipient_pub_bytes.copy_to(salt[32, 32])

        wrap_key = Age::HKDF.sha256(shared, salt, Age::X25519_INFO.to_slice, 32)
        zero_nonce = Bytes.new(12)
        wrapped = Age::ChaCha20Poly1305.encrypt(wrap_key, zero_nonce, challenge)

        {ephem_pub, wrapped}
      end

      # Unwrap a challenge using the client's AGE secret key.
      # Returns the plaintext challenge if successful.
      def self.unwrap(ephemeral_pub : Bytes, wrapped : Bytes, secret_key_bytes : Bytes) : Bytes
        raise Error.new("Ephemeral pubkey must be 32 bytes") unless ephemeral_pub.size == 32
        raise Error.new("Wrapped must be 48 bytes") unless wrapped.size == 48
        raise Error.new("Secret key must be 32 bytes") unless secret_key_bytes.size == 32

        shared = Age::X25519.shared_secret(secret_key_bytes, ephemeral_pub)

        pub_bytes = Age::X25519.public_from_private(secret_key_bytes)
        salt = Bytes.new(64)
        ephemeral_pub.copy_to(salt[0, 32])
        pub_bytes.copy_to(salt[32, 32])

        wrap_key = Age::HKDF.sha256(shared, salt, Age::X25519_INFO.to_slice, 32)
        zero_nonce = Bytes.new(12)
        Age::ChaCha20Poly1305.decrypt(wrap_key, zero_nonce, wrapped)
      end
    end
  end
end
