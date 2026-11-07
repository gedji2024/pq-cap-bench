"""Start a command detached from the calling shell: new session (setsid), stdin from /dev/null, output to a log.
Usage: /usr/bin/python3 detach.py <log> <cmd> [args...]   (prints the PID of the detached process)"""
import os
import sys

log, cmd = sys.argv[1], sys.argv[2:]
pid = os.fork()
if pid:
    print(pid)
    sys.exit(0)
os.setsid()
fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
os.dup2(os.open(os.devnull, os.O_RDONLY), 0)
os.dup2(fd, 1)
os.dup2(fd, 2)
os.execvp(cmd[0], cmd)
