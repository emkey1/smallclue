import pty
import os
import time

pid, fd = pty.fork()
if pid == 0:
    os.execv("./smallclue", ["./smallclue", "md", "/home/jules/Docs/test.md"])
else:
    time.sleep(0.5)
    # Open links menu
    os.write(fd, b"o")
    time.sleep(0.5)
    out = b""
    while True:
        try:
            data = os.read(fd, 1024)
            out += data
            if b"Links" in out:
                break
        except OSError:
            break
    os.write(fd, b"q")
    os.write(fd, b"q")
    os.waitpid(pid, 0)
    print("Output captured:")
    print(out.decode('utf-8', 'replace'))
