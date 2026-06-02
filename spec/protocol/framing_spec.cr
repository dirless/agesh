require "../spec_helper"

describe AgeSh::Framer do
  describe ".write_message / .read_message" do
    it "round-trips a small payload" do
      io = IO::Memory.new
      payload = Bytes[0x01, 0x02, 0x03]
      AgeSh::Framer.write_message(io, payload)
      io.rewind
      result = AgeSh::Framer.read_message(io)
      result.should eq(payload)
    end

    it "round-trips a larger payload" do
      io = IO::Memory.new
      payload = Random::Secure.random_bytes(4096)
      AgeSh::Framer.write_message(io, payload)
      io.rewind
      result = AgeSh::Framer.read_message(io)
      result.should eq(payload)
    end

    it "round-trips an empty payload" do
      io = IO::Memory.new
      payload = Bytes.new(0)
      AgeSh::Framer.write_message(io, payload)
      io.rewind
      result = AgeSh::Framer.read_message(io)
      result.size.should eq(0)
    end

    it "round-trips multiple messages sequentially" do
      io = IO::Memory.new
      messages = [
        Bytes[0x01],
        Bytes[0xFF, 0xFE, 0xFD, 0xFC],
        Random::Secure.random_bytes(1024),
        Bytes.new(0),
      ]
      messages.each { |m| AgeSh::Framer.write_message(io, m) }
      io.rewind
      messages.each do |expected|
        result = AgeSh::Framer.read_message(io)
        result.should eq(expected)
      end
    end
  end

  describe ".read_message" do
    it "raises on unexpected EOF" do
      io = IO::Memory.new(Bytes[0x00, 0x00, 0x01, 0x00]) # length=256 but no data
      io.rewind
      expect_raises(AgeSh::Error, /Unexpected EOF/) do
        AgeSh::Framer.read_message(io)
      end
    end
  end
end
