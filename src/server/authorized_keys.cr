require "age-crystal"

module AgeSh
  # Parse ~/.age/authorized_keys — one age1... public key per line.
  # Comments (#), blank lines, and inline comments (# after key) are supported.
  module AuthorizedKeys
    # Parse the authorized_keys file and return an array of public keys.
    # Returns an empty array if the file doesn't exist.
    def self.parse(path : String) : Array(Age::PublicKey)
      return [] of Age::PublicKey unless File.exists?(path)

      keys = [] of Age::PublicKey
      File.each_line(path) do |line|
        line = line.strip
        next if line.empty? || line.starts_with?('#')

        # Strip inline comments
        if idx = line.index('#')
          line = line[0, idx].strip
        end
        next if line.empty?

        begin
          keys << Age::PublicKey.new(line)
        rescue ex : Age::Error
          # Skip invalid lines silently
          next
        end
      end
      keys
    end

    # Check if a given public key string is in the authorized keys list.
    def self.authorized?(path : String, pubkey_str : String) : Bool
      parse(path).any? { |k| k.value == pubkey_str }
    end
  end
end
