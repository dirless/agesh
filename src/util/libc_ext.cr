# Consolidated LibC extensions — only declares functions and structs
# that Crystal's stdlib does NOT already provide.

lib LibC
  # PTY functions
  fun posix_openpt(flags : Int32) : Int32
  fun grantpt(fd : Int32) : Int32
  fun unlockpt(fd : Int32) : Int32
  fun ptsname(fd : Int32) : Char*

  # Process control
  fun setsid : PidT
  fun setgid(gid : GidT) : Int32
  fun setuid(uid : UidT) : Int32
  fun chdir(path : Char*) : Int32
  fun prctl(option : Int32, arg : UInt64, ...) : Int32
  fun execvp(file : Char*, argv : Char**) : Int32

  # User/group functions
  fun initgroups(user : Char*, group : GidT) : Int32
  fun getpwnam(name : Char*) : Passwd*
  fun execve(path : Char*, argv : Char**, envp : Char**) : Int32

  # Terminal functions
  fun tcgetattr(fd : Int32, termios_p : Termios*) : Int32
  fun tcsetattr(fd : Int32, optional_actions : Int32, termios_p : Termios*) : Int32
  fun ioctl(fd : Int32, request : Long, ...) : Int32

  # Constants that may not be in Crystal's stdlib
  PR_SET_PDEATHSIG =      1
  TIOCSCTTY        = 0x540E
  TIOCGWINSZ       = 0x5413
  TIOCSWINSZ       = 0x5414
  VTIME            =      5 # termios c_cc index: read timeout (tenths of a second)
end

# Pty module uses LibC constants already defined by Crystal
module AgeSh
  module PTY
    O_RDWR = LibC::O_RDWR

    struct Winsize
      property ws_row : UInt16
      property ws_col : UInt16
      property ws_xpixel : UInt16
      property ws_ypixel : UInt16

      def initialize(@ws_row = 24_u16, @ws_col = 80_u16, @ws_xpixel = 0_u16, @ws_ypixel = 0_u16)
      end
    end

    def self.allocate : {Int32, String}
      master_fd = LibC.posix_openpt(O_RDWR)
      raise Error.new("posix_openpt failed: #{Errno.value}") if master_fd < 0

      if LibC.grantpt(master_fd) < 0
        LibC.close(master_fd)
        raise Error.new("grantpt failed: #{Errno.value}")
      end

      if LibC.unlockpt(master_fd) < 0
        LibC.close(master_fd)
        raise Error.new("unlockpt failed: #{Errno.value}")
      end

      slave_path = String.new(LibC.ptsname(master_fd))
      Logger.debug("PTY allocated: master=#{master_fd} slave=#{slave_path}")

      {master_fd, slave_path}
    end

    def self.get_winsize(fd : Int32) : Winsize
      ws = Winsize.new
      ret = LibC.ioctl(fd, LibC::TIOCGWINSZ, pointerof(ws).as(Void*))
      raise Error.new("ioctl(TIOCGWINSZ) failed: #{Errno.value}") if ret < 0
      ws
    end

    def self.set_winsize(fd : Int32, rows : UInt32, cols : UInt32) : Nil
      ws = Winsize.new(rows.to_u16, cols.to_u16)
      ret = LibC.ioctl(fd, LibC::TIOCSWINSZ, pointerof(ws).as(Void*))
      raise Error.new("ioctl(TIOCSWINSZ) failed: #{Errno.value}") if ret < 0
    end
  end
end
