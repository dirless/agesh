require "spec"
require "../src/agesh"

# Helper IO that reads from one stream and writes to another.
# Used to simulate bidirectional communication in tests.
class DuplexIO < IO
  def initialize(@input : IO, @output : IO)
  end

  def read(slice : Bytes)
    @input.read(slice)
  end

  def write(slice : Bytes) : Nil
    @output.write(slice)
  end

  def flush
    @output.flush
  end
end
