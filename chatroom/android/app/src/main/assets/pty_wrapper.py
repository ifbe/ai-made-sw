#!/system/xbin/python3
import os
import sys
import select
import fcntl
import termios
import struct
import pty
import tty
import signal

# Disable output buffering
sys.stdout = os.fdopen(sys.stdout.fileno(), 'wb', buffering=0)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'wb', buffering=0)

def set_window_size(fd, rows, cols):
    winsize = struct.pack('HHHH', rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

# Create PTY
master_fd, slave_fd = pty.openpty()
tty.setraw(master_fd)
tty.setraw(slave_fd)

# Fork child process
pid = os.fork()

if pid == 0:
    # Child: close master, set up slave as PTY
    os.close(master_fd)
    os.setsid()
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
    os.dup2(slave_fd, 0)
    os.dup2(slave_fd, 1)
    os.dup2(slave_fd, 2)
    if slave_fd > 2:
        os.close(slave_fd)

    shell = sys.argv[1] if len(sys.argv) > 1 else '/system/bin/sh'
    os.execv(shell, [shell])

else:
    # Parent
    os.close(slave_fd)

    # Send ready signal
    sys.stdout.write(b'READY\n')
    sys.stdout.flush()

    def cleanup(signum, frame):
        os.close(master_fd)
        os.waitpid(pid, 0)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    # Non-blocking read loop
    while True:
        r, _, _ = select.select([master_fd, sys.stdin], [], [])
        if master_fd in r:
            try:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                encoded = data.decode('utf-8', errors='replace')
                for line in encoded.split('\r\n'):
                    if line:
                        sys.stdout.write(('OUTPUT:' + line + '\n').encode())
                        sys.stdout.flush()
            except OSError:
                break
        if sys.stdin in r:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.rstrip('\n\r')
                if line.startswith('RESIZE:'):
                    parts = line.split(':')
                    if len(parts) == 3:
                        set_window_size(master_fd, int(parts[1]), int(parts[2]))
                elif line.startswith('INPUT:'):
                    cmd = line[6:].encode('utf-8')
                    os.write(master_fd, cmd + b'\n')
                elif line == 'WINCH':
                    rows, cols = os.popen('stty size', 'r').read().split()
                    set_window_size(master_fd, int(rows), int(cols))
                elif line == 'EXIT':
                    os.close(master_fd)
                    os.waitpid(pid, 0)
                    break
            except OSError:
                break

    os.close(master_fd)
    os.waitpid(pid, 0)
