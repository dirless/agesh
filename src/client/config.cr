module AgeSh
  module Client
    struct Config
      getter host : String
      getter port : Int32
      getter username : String
      getter identity_file : String

      def initialize(@host : String, @port : Int32, @username : String, @identity_file : String)
      end
    end
  end
end
