require "age-crystal"

module AgeSh
  # Challenge-response authentication using AGE identity keys.
  #
  # The server wraps a random challenge using the client's AGE public key
  # (same X25519+HKDF+ChaCha20Poly1305 flow as AGE file encryption).
  # The client unwraps it to prove possession of the corresponding secret key.
  module Authentication
    # Client-side authentication. Proves possession of the AGE secret key.
    # Raises Error on auth failure.
    def self.client(
      transport : Transport::Session,
      io : IO,
      username : String,
      pubkey_str : String,
      secret_key_bytes : Bytes,
      pub_bytes : Bytes,
    ) : Nil
      # Send auth request
      request = Messages.write_auth_request(username, pubkey_str)
      encrypted_request = transport.send_record(Constants::TAG_DATA, request)
      Framer.write_message(io, encrypted_request)

      # Read auth challenge (or rejection if key is unauthorized)
      encrypted_challenge = Framer.read_message(io)
      _, challenge_data = transport.recv_record(encrypted_challenge)
      if challenge_data[0] == Constants::MSG_AUTH_RESULT
        success, message = Messages.read_auth_result(challenge_data)
        raise Error.new("Auth failed: #{message}") unless success
      end
      challenge, ephemeral_pub, wrapped = Messages.read_auth_challenge(challenge_data)

      # Unwrap the challenge using our secret key (pass pub_bytes to skip redundant scalar mult)
      decrypted = Crypto::AuthWrap.unwrap(ephemeral_pub, wrapped, secret_key_bytes, pub_bytes)

      # Verify it matches the plaintext challenge (constant-time)
      raise Error.new("Auth failed: challenge mismatch") unless constant_time_eq(decrypted, challenge)

      # Send the decrypted challenge as proof
      response = Messages.write_auth_response(decrypted)
      encrypted_response = transport.send_record(Constants::TAG_DATA, response)
      Framer.write_message(io, encrypted_response)

      # Read auth result
      encrypted_result = Framer.read_message(io)
      _, result_data = transport.recv_record(encrypted_result)
      success, message = Messages.read_auth_result(result_data)

      raise Error.new("Auth failed: #{message}") unless success

      Logger.debug("Client authentication successful")
    end

    # Server-side authentication. Returns the username on success.
    # key_resolver is called with the username and returns the authorized_keys path to
    # check, or nil to skip the check (e.g. for testing).
    # Raises Error on auth failure.
    def self.server(
      transport : Transport::Session,
      io : IO,
      key_resolver : Proc(String, String?),
    ) : String
      # Read auth request
      encrypted_request = Framer.read_message(io)
      _, request_data = transport.recv_record(encrypted_request)
      username, pubkey_str = Messages.read_auth_request(request_data)

      Logger.info("Auth attempt: user=#{username} key=#{pubkey_str[0..20]}...")

      # Parse the public key to get raw bytes
      begin
        pubkey = Age::PublicKey.new(pubkey_str)
        _, pub_bytes = Age::Bech32.decode(pubkey_str)
      rescue ex : Age::Error
        send_auth_result(transport, io, false, "Invalid public key format")
        raise Error.new("Invalid public key format from #{username}")
      end

      # Check authorized_keys using the per-user path returned by the resolver
      if path = key_resolver.call(username)
        unless AuthorizedKeys.authorized?(path, pubkey_str)
          send_auth_result(transport, io, false, "Key not authorized")
          raise Error.new("Unauthorized key for #{username}")
        end
      end

      # Generate challenge and wrap it
      challenge = Random::Secure.random_bytes(Constants::CHALLENGE_SIZE)
      ephemeral_pub, wrapped = Crypto::AuthWrap.wrap(challenge, pub_bytes)

      # Send challenge
      challenge_msg = Messages.write_auth_challenge(challenge, ephemeral_pub, wrapped)
      encrypted_challenge = transport.send_record(Constants::TAG_DATA, challenge_msg)
      Framer.write_message(io, encrypted_challenge)

      # Read response
      encrypted_response = Framer.read_message(io)
      _, response_data = transport.recv_record(encrypted_response)
      response = Messages.read_auth_response(response_data)

      # Verify response matches challenge
      if constant_time_eq(response, challenge)
        send_auth_result(transport, io, true)
        Logger.info("Auth success: user=#{username}")
        username
      else
        send_auth_result(transport, io, false, "Challenge verification failed")
        raise Error.new("Challenge verification failed for #{username}")
      end
    end

    private def self.send_auth_result(transport, io, success, message = "")
      result = Messages.write_auth_result(success, message)
      encrypted = transport.send_record(Constants::TAG_DATA, result)
      Framer.write_message(io, encrypted)
    end

    private def self.constant_time_eq(a : Bytes, b : Bytes) : Bool
      return false if a.size != b.size
      diff = 0_u8
      a.size.times { |i| diff |= a[i] ^ b[i] }
      diff == 0
    end
  end
end
