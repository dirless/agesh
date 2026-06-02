module AgeSh
  module Client
    # Manages the local terminal: raw mode, winsize, SIGWINCH handling.
    module Terminal
      @@winsize_rows : UInt32 = 24
      @@winsize_cols : UInt32 = 80
      @@saved_termios : LibC::Termios = LibC::Termios.new
      @@termios_saved : Bool = false

      # Save current terminal state and enter raw mode.
      # Yields to the block, then restores the terminal on exit.
      # Also installs SIGTERM/SIGHUP handlers so the terminal is always restored.
      def self.raw(&)
        original = LibC::Termios.new
        if LibC.tcgetattr(0, pointerof(original)) != 0
          raise Error.new("Failed to get terminal attributes")
        end

        # Enter raw mode
        raw = original
        raw.c_lflag &= ~(LibC::ICANON | LibC::ECHO | LibC::ISIG)
        raw.c_iflag &= ~(LibC::ICRNL | LibC::IXON)
        raw.c_oflag &= ~LibC::OPOST
        raw.c_cc[LibC::VMIN] = 1
        raw.c_cc[LibC::VTIME] = 0

        if LibC.tcsetattr(0, LibC::TCSANOW, pointerof(raw)) != 0
          raise Error.new("Failed to set terminal to raw mode")
        end

        @@saved_termios = original
        @@termios_saved = true

        # Get initial window size
        update_winsize

        # Restore terminal on SIGTERM/SIGHUP so the shell isn't left in raw mode.
        Signal::TERM.trap { restore; LibC._exit(0) }
        Signal::HUP.trap { restore; LibC._exit(0) }

        begin
          yield
        ensure
          restore
          Signal::TERM.reset
          Signal::HUP.reset
        end
      end

      # Restore saved terminal attributes (safe to call multiple times).
      def self.restore : Nil
        return unless @@termios_saved
        orig = @@saved_termios
        LibC.tcsetattr(0, LibC::TCSANOW, pointerof(orig))
        @@termios_saved = false
      end

      # Get current window size.
      def self.winsize : {UInt32, UInt32}
        {@@winsize_rows, @@winsize_cols}
      end

      # Update cached window size from the actual terminal.
      def self.update_winsize : Nil
        ws = PTY::Winsize.new
        if LibC.ioctl(0, LibC::TIOCGWINSZ, pointerof(ws).as(Void*)) == 0
          @@winsize_rows = ws.ws_row.to_u32
          @@winsize_cols = ws.ws_col.to_u32
        end
      end

      # Get the TERM environment variable.
      def self.term_type : String
        ENV.fetch("TERM", "xterm-256color")
      end
    end
  end
end
