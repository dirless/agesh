require "io/memory"

module AgeSh
  module Messages
    # Version message: [type=0x01][version=u8][reserved=2 bytes]
    def self.write_version(version : UInt8 = Constants::PROTOCOL_VERSION) : Bytes
      Bytes[Constants::MSG_VERSION, version, 0_u8, 0_u8]
    end

    def self.read_version(data : Bytes) : {UInt8, UInt8}
      raise Error.new("Version message too short") if data.size < 4
      raise Error.new("Not a version message") unless data[0] == Constants::MSG_VERSION
      {data[1], data[2]} # version, reserved
    end

    # Key exchange message: [type=0x10][ephemeral_public_key: 32 bytes]
    def self.write_key_exchange(ephemeral_pub : Bytes) : Bytes
      raise Error.new("Ephemeral key must be 32 bytes") unless ephemeral_pub.size == 32
      msg = Bytes.new(33)
      msg[0] = Constants::MSG_KEY_EXCHANGE
      ephemeral_pub.copy_to(msg[1, 32])
      msg
    end

    def self.read_key_exchange(data : Bytes) : Bytes
      raise Error.new("Key exchange message too short") if data.size < 33
      raise Error.new("Not a key exchange message") unless data[0] == Constants::MSG_KEY_EXCHANGE
      data[1, 32]
    end

    # Auth request: [type=0x20][username: null-terminated][age_pubkey: null-terminated]
    def self.write_auth_request(username : String, pubkey : String) : Bytes
      io = IO::Memory.new
      io.write_byte(Constants::MSG_AUTH_REQUEST)
      io.print(username)
      io.write_byte(0_u8)
      io.print(pubkey)
      io.write_byte(0_u8)
      io.to_slice
    end

    def self.read_auth_request(data : Bytes) : {String, String}
      raise Error.new("Auth request too short") if data.size < 2
      raise Error.new("Not an auth request") unless data[0] == Constants::MSG_AUTH_REQUEST
      payload = data[1, data.size - 1]
      # Find first null — that separates username from pubkey
      null_idx = payload.index(0_u8) || raise Error.new("Malformed auth request: no null separator")
      username = String.new(payload[0, null_idx])
      pubkey = String.new(payload[null_idx + 1, payload.size - null_idx - 1]).rstrip('\0')
      {username, pubkey}
    end

    # Auth challenge: [type=0x21][challenge: 32 bytes][ephemeral_pub: 32 bytes][wrapped: 48 bytes]
    def self.write_auth_challenge(challenge : Bytes, ephemeral_pub : Bytes, wrapped : Bytes) : Bytes
      raise Error.new("Challenge must be 32 bytes") unless challenge.size == 32
      raise Error.new("Ephemeral pub must be 32 bytes") unless ephemeral_pub.size == 32
      raise Error.new("Wrapped must be 48 bytes (32 + 16 tag)") unless wrapped.size == 48
      msg = Bytes.new(1 + 32 + 32 + 48)
      msg[0] = Constants::MSG_AUTH_CHALLENGE
      challenge.copy_to(msg[1, 32])
      ephemeral_pub.copy_to(msg[33, 32])
      wrapped.copy_to(msg[65, 48])
      msg
    end

    def self.read_auth_challenge(data : Bytes) : {Bytes, Bytes, Bytes}
      expected = 1 + 32 + 32 + 48
      raise Error.new("Auth challenge wrong size: #{data.size}, expected #{expected}") if data.size < expected
      raise Error.new("Not an auth challenge") unless data[0] == Constants::MSG_AUTH_CHALLENGE
      {data[1, 32], data[33, 32], data[65, 48]}
    end

    # Auth response: [type=0x22][response: 32 bytes]
    def self.write_auth_response(response : Bytes) : Bytes
      raise Error.new("Response must be 32 bytes") unless response.size == 32
      msg = Bytes.new(33)
      msg[0] = Constants::MSG_AUTH_RESPONSE
      response.copy_to(msg[1, 32])
      msg
    end

    def self.read_auth_response(data : Bytes) : Bytes
      raise Error.new("Auth response too short") if data.size < 33
      raise Error.new("Not an auth response") unless data[0] == Constants::MSG_AUTH_RESPONSE
      data[1, 32]
    end

    # Auth result: [type=0x23][status: u8][message: null-terminated]
    def self.write_auth_result(success : Bool, message : String = "") : Bytes
      io = IO::Memory.new
      io.write_byte(Constants::MSG_AUTH_RESULT)
      io.write_byte(success ? 0x00_u8 : 0x01_u8)
      unless message.empty?
        io.print(message)
      end
      io.write_byte(0_u8)
      io.to_slice
    end

    def self.read_auth_result(data : Bytes) : {Bool, String}
      raise Error.new("Auth result too short") if data.size < 3
      raise Error.new("Not an auth result") unless data[0] == Constants::MSG_AUTH_RESULT
      success = data[1] == 0x00_u8
      message = data.size > 2 ? String.new(data[2, data.size - 2]).rstrip('\0') : ""
      {success, message}
    end

    # Session setup: [type=0x30][term_type: null-terminated][rows: u32 BE][cols: u32 BE][env_count: u16 BE][env: ...]
    def self.write_session_setup(term_type : String, rows : UInt32, cols : UInt32, env : Hash(String, String)) : Bytes
      io = IO::Memory.new
      io.write_byte(Constants::MSG_SESSION_SETUP)
      io.print(term_type)
      io.write_byte(0_u8)
      io.write_bytes(rows, IO::ByteFormat::BigEndian)
      io.write_bytes(cols, IO::ByteFormat::BigEndian)
      io.write_bytes(env.size.to_u16, IO::ByteFormat::BigEndian)
      env.each do |key, value|
        io.print(key)
        io.write_byte(0_u8)
        io.print(value)
        io.write_byte(0_u8)
      end
      io.to_slice
    end

    def self.read_session_setup(data : Bytes) : {String, UInt32, UInt32, Hash(String, String)}
      raise Error.new("Session setup too short") if data.size < 12
      raise Error.new("Not a session setup") unless data[0] == Constants::MSG_SESSION_SETUP
      payload = data[1, data.size - 1]
      reader = IO::Memory.new(payload)
      term_type = reader.gets('\0') || ""
      rows = reader.read_bytes(UInt32, IO::ByteFormat::BigEndian)
      cols = reader.read_bytes(UInt32, IO::ByteFormat::BigEndian)
      env_count = reader.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      env = Hash(String, String).new
      env_count.times do
        key = reader.gets('\0') || ""
        value = reader.gets('\0') || ""
        env[key] = value
      end
      {term_type, rows, cols, env}
    end

    # Session ready: [type=0x31][status: u8]
    def self.write_session_ready : Bytes
      Bytes[Constants::MSG_SESSION_READY, 0x00_u8]
    end

    def self.read_session_ready(data : Bytes) : Bool
      raise Error.new("Session ready too short") if data.size < 2
      raise Error.new("Not a session ready") unless data[0] == Constants::MSG_SESSION_READY
      data[1] == 0x00_u8
    end
  end
end
