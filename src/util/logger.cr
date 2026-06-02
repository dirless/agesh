module AgeSh
  module Logger
    {% begin %}
      {% if flag?(:debug) %}
        LEVEL = 0
      {% else %}
        LEVEL = 1
      {% end %}
    {% end %}

    DEBUG = 0
    INFO  = 1
    WARN  = 2
    ERROR = 3

    def self.debug(msg : String)
      return if LEVEL > DEBUG
      STDERR.puts "[DEBUG] #{msg}"
    end

    def self.info(msg : String)
      return if LEVEL > INFO
      STDERR.puts "[INFO] #{msg}"
    end

    def self.warn(msg : String)
      return if LEVEL > WARN
      STDERR.puts "[WARN] #{msg}"
    end

    def self.error(msg : String)
      STDERR.puts "[ERROR] #{msg}"
    end
  end
end
