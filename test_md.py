import pty
import os
import time

def read_output(fd):
    out = b""
    while True:
        try:
            data = os.read(fd, 1024)
            out += data
        except OSError:
            break
        if not data:
            break
        if b"Markdown docs" in out or b"Links in" in out:
            time.sleep(0.5)
            # send q to quit menu
            os.write(fd, b"q")
            time.sleep(0.5)
            os.write(fd, b"q")
            break
    return out

pid, fd = pty.fork()
if pid == 0:
    os.execv("./smallclue", ["./smallclue", "md", "-i"])
else:
    out = read_output(fd)
    os.waitpid(pid, 0)
    print("Output captured:")
    print(out.decode('utf-8', 'replace'))
