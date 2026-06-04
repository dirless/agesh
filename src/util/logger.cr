module AgeSh
  module Logger
    DEBUG = 0
    INFO  = 1
    WARN  = 2
    ERROR = 3

    # Runtime log level. Defaults to DEBUG for -Ddebug builds, INFO otherwise,
    # and can be overridden at startup (e.g. an `--debug` CLI flag).
    {% begin %}
      {% if flag?(:debug) %}
        @@level = 0
      {% else %}
        @@level = 1
      {% end %}
    {% end %}

    def self.level=(level : Int32) : Nil
      @@level = level
    end

    def self.level : Int32
      @@level
    end

    def self.debug(msg : String)
      return if @@level > DEBUG
      STDERR.puts "[DEBUG] #{msg}"
    end

    def self.info(msg : String)
      return if @@level > INFO
      STDERR.puts "[INFO] #{msg}"
    end

    def self.warn(msg : String)
      return if @@level > WARN
      STDERR.puts "[WARN] #{msg}"
    end

    def self.error(msg : String)
      STDERR.puts "[ERROR] #{msg}"
    end
  end
end
