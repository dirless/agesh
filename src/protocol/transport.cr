require "age-crystal"

module AgeSh
  # Counter-based ChaCha20-Poly1305 transport cipher.
  #
  # Each direction (send/recv) uses a unique key derived via HKDF from the
  # transport key, with a 4-byte counter in the last 4 bytes of a 12-byte nonce.
  # This gives 2^32 records per direction (256 TiB at 64 KiB per record).
  module Transport
    NONCE_SIZE = 12
    TAG_SIZE   = 16 # Poly1305 tag

    enum Role
      Client
      Server
    end

    # One direction of the encrypted channel.
    class Direction
      getter key : Bytes
      getter counter : UInt32

      def initialize(@key : Bytes)
        @counter = 0_u32
      end

      # Build the next nonce: [8 zero bytes][4-byte BE counter]
      private def next_nonce : Bytes
        raise Error.new("Transport counter exhausted") if @counter == UInt32::MAX
        nonce = Bytes.new(NONCE_SIZE)
        IO::ByteFormat::BigEndian.encode(@counter, nonce[8, 4])
        @counter += 1
        nonce
      end

      # Encrypt a payload. Returns ciphertext + tag.
      def encrypt(payload : Bytes) : Bytes
        nonce = next_nonce
        Age::ChaCha20Poly1305.encrypt(@key, nonce, payload)
      end

      # Decrypt a record (ciphertext + tag). Returns plaintext.
      def decrypt(record : Bytes) : Bytes
        raise Error.new("Record too short for Poly1305 tag") if record.size < TAG_SIZE
        nonce = next_nonce
        begin
          Age::ChaCha20Poly1305.decrypt(@key, nonce, record)
        rescue ex : Age::Error
          raise Error.new(ex.message)
        end
      end
    end

    # Full bidirectional transport session with separate send/recv directions.
    #
    # The role parameter ensures that:
    #   client.send_key == server.recv_key
    #   server.send_key == client.recv_key
    class Session
      getter send : Direction
      getter recv : Direction

      def initialize(transport_key : Bytes, @role : Role)
        # Client sends with SEND_INFO, server receives with SEND_INFO.
        # Server sends with RECV_INFO, client receives with RECV_INFO.
        send_key = Age::HKDF.sha256(transport_key, Constants::SEND_INFO.to_slice, Bytes.new(0), 32)
        recv_key = Age::HKDF.sha256(transport_key, Constants::RECV_INFO.to_slice, Bytes.new(0), 32)

        case @role
        in Role::Client
          @send = Direction.new(send_key)
          @recv = Direction.new(recv_key)
        in Role::Server
          @send = Direction.new(recv_key)
          @recv = Direction.new(send_key)
        end
      end

      # Encrypt a framed message through the send direction.
      # Wire format: encrypted [1 byte tag][payload] + tag
      def send_record(tag : UInt8, payload : Bytes) : Bytes
        inner = Bytes.new(1 + payload.size)
        inner[0] = tag
        payload.copy_to(inner[1, payload.size])
        @send.encrypt(inner)
      end

      # Decrypt a received record. Returns {tag, payload}.
      def recv_record(record : Bytes) : {UInt8, Bytes}
        decrypted = @recv.decrypt(record)
        raise Error.new("Decrypted record too short") if decrypted.size < 1
        {decrypted[0], decrypted[1, decrypted.size - 1]}
      end
    end
  end
end
