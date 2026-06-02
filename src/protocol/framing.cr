module AgeSh
  # Length-prefixed message framing: [4 bytes big-endian length][payload].
  #
  # Used for pre-session protocol messages (raise on error) and the data
  # channel proxy (return bool for clean EOF handling).
  module Framer
    @@header_buf = Bytes.new(4)

    # Write a length-prefixed message to the IO.
    def self.write_message(io : IO, payload : Bytes) : Nil
      raise Error.new("Payload too large: #{payload.size} > #{Constants::MAX_RECORD_SIZE}") if payload.size > Constants::MAX_RECORD_SIZE
      write_record(io, payload)
    end

    # Read a length-prefixed message from the IO.
    # Raises Error on EOF or oversized frame.
    def self.read_message(io : IO) : Bytes
      buf = @@header_buf
      unless read_exact(io, buf)
        raise Error.new("Unexpected EOF reading frame header")
      end
      length = IO::ByteFormat::BigEndian.decode(UInt32, buf)
      raise Error.new("Frame too large: #{length} > #{Constants::MAX_RECORD_SIZE}") if length > Constants::MAX_RECORD_SIZE
      payload = Bytes.new(length)
      if length > 0
        unless read_exact(io, payload)
          raise Error.new("Unexpected EOF reading frame payload")
        end
      end
      payload
    end

    # Write a raw length-prefixed record: [4-byte BE length][data].
    # Used by the data channel proxy (and by write_message).
    def self.write_record(io : IO, data : Bytes) : Nil
      IO::ByteFormat::BigEndian.encode(data.size.to_u32, @@header_buf)
      io.write(@@header_buf)
      io.write(data)
      io.flush
    end

    # Read exactly `buf.size` bytes, returning false on EOF (true on success).
    # Used by the data channel proxy.
    def self.read_exact(io : IO, buf : Bytes) : Bool
      offset = 0
      while offset < buf.size
        count = io.read(buf[offset, buf.size - offset])
        return false if count.nil? || count == 0
        offset += count
      end
      true
    end
  end
end
