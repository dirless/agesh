module AgeSh
  module Constants
    VERSION          = "0.0.3"
    PROTOCOL_VERSION = 1_u8
    DEFAULT_PORT     = 2202

    # Message types
    MSG_VERSION        = 0x01_u8
    MSG_VERSION_ACK    = 0x02_u8
    MSG_KEY_EXCHANGE   = 0x10_u8
    MSG_AUTH_REQUEST   = 0x20_u8
    MSG_AUTH_CHALLENGE = 0x21_u8
    MSG_AUTH_RESPONSE  = 0x22_u8
    MSG_AUTH_RESULT    = 0x23_u8
    MSG_SESSION_SETUP  = 0x30_u8
    MSG_SESSION_READY  = 0x31_u8

    # Data channel tags
    TAG_DATA          = 0x00_u8
    TAG_WINDOW_RESIZE = 0x01_u8
    TAG_SESSION_END   = 0xFF_u8

    # Transport
    MAX_RECORD_SIZE = 64 * 1024
    CHALLENGE_SIZE  = 32
    NONCE_SIZE      = 12

    # HKDF info strings
    TRANSPORT_INFO = "age-terminal.org/v1/transport"
    SEND_INFO      = "age-terminal.org/v1/send"
    RECV_INFO      = "age-terminal.org/v1/recv"

    # Paths
    AUTHORIZED_KEYS_DIR  = ".age"
    AUTHORIZED_KEYS_FILE = "authorized_keys"

    # Identity defaults
    DEFAULT_IDENTITY_FILE = ".age/identity"
  end

  class Error < Exception; end
end
