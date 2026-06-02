module AgeSh
  module Server
    struct Config
      getter bind_address : String
      getter port : Int32

      def initialize(@bind_address : String = "0.0.0.0", @port : Int32 = Constants::DEFAULT_PORT)
      end
    end
  end
end
