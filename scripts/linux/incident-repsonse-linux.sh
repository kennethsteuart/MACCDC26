```bash
#!/usr/bin/env bash
# Incident Response Playbook - Linux
# Usage: sudo ./incident-response-linux.sh
# Replace ATTACKER_IP, ADMIN_IP, MALICIOUS_USER, PID as needed

set -euo pipefail

ATTACKER_IP="ATTACKER_IP"
ADMIN_IP="ADMIN_IP"
MALICIOUS_USER="MALICIOUS_USER"
PID_TO_KILL="PID"

echo "[+] Starting Linux Incident Response Actions"

#######################################
# Phase 2: Containment
#######################################

echo "[+] Backing up current iptables rules"
iptables-save > /tmp/iptables.backup

echo "[+] Isolating host (allow SSH from admin only)"
iptables -F
iptables -A INPUT -s "$ADMIN_IP" -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -j DROP

iptables -A OUTPUT -d "$ADMIN_IP" -p tcp --sport 22 -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -j DROP

#######################################
# Kill Active Sessions
#######################################

echo "[+] Logged in users:"
who || true

if id "$MALICIOUS_USER" &>/dev/null; then
  echo "[+] Killing sessions for user: $MALICIOUS_USER"
  pkill -KILL -u "$MALICIOUS_USER" || true
fi

if [[ "$PID_TO_KILL" != "PID" ]]; then
  echo "[+] Killing PID $PID_TO_KILL"
  kill -9 "$PID_TO_KILL" || true
fi

#######################################
# Phase 3: Eradication Checks
#######################################

echo "[+] Checking cron jobs"
crontab -l || true
crontab -l -u root || true
ls -la /etc/cron.* || true
cat /etc/crontab || true

echo "[+] Checking systemd services"
systemctl list-unit-files --state=enabled
systemctl list-units --type=service --state=running
ls -la ~/.config/systemd/user/ 2>/dev/null || true

echo "[+] Checking SSH authorized_keys"
for user in $(cut -f1 -d: /etc/passwd); do
  home=$(eval echo "~$user" 2>/dev/null || true)
  if [[ -f "$home/.ssh/authorized_keys" ]]; then
    echo "=== $user ==="
    cat "$home/.ssh/authorized_keys"
  fi
done

echo "[+] Checking for UID 0 users"
awk -F: '$3 == 0 {print $1}' /etc/passwd

echo "[+] Checking login-capable users"
grep -v '/nologin\|/false' /etc/passwd

echo "[+] Checking SUID binaries"
find / -perm -4000 -type f 2>/dev/null

echo "[+] Checking /tmp and /var/tmp"
ls -la /tmp/
ls -la /var/tmp/
find /tmp -type f -executable 2>/dev/null

#######################################
# Phase 4: Recovery
#######################################

echo "[+] To restore firewall when safe:"
echo "    iptables-restore < /tmp/iptables.backup"

echo "[+] Linux incident response script completed"
```
