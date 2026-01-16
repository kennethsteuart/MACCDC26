General
Pre-Tasks:
Identify all necessary SSH users
Enforce least privilege (no unnecessary sudoers)
grep -E 'sudo|wheel' /etc/group (shows whos sudo)
Disable root SSH login
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config (disables root SSH)
sudo systemctl restart sshd (applies changes)
Update all system packages
sudo apt update && sudo apt upgrade -y (Debian/Ubuntu)
sudo dnf update -y (Fedora/RHEL)

Minutes 1-10: Firewall Baseline (Default Deny)
Enable the Linux firewall service
sudo systemctl enable --now firewalld
Set the active zone to public
sudo firewall-cmd --set-default-zone=public
Set default inbound policy to deny all
sudo firewall-cmd --zone=public --set-target=DROP
Log all denied firewall packets
sudo firewall-cmd --set-log-denied=all
Reload firewall to apply changes
sudo firewall-cmd --reload
Verify all firewall settings
sudo firewall-cmd --list-all

Minutes 11-20: Accounts, Passwords, Lockouts
Edit password complexity rules
sudo nano /etc/security/pwquality.conf
Edit password age settings
sudo nano /etc/login.defs
Configure lockout policies
sudo nano /etc/pam.d/system-auth
sudo nano /etc/pam.d/password-auth
Lock necessary accounts
sudo usermod -L username
Remove shell access for system accounts
sudo usermod -s /sbin/nologin account

Minutes 21–30: Disable Pivots & Lateral Movement Services
Disable print services
sudo systemctl disable --now cups
Disable mDNs/LLMNR services (name spoofing attacks)
sudo systemctl disable --now avahi-daemon
Disable NFS server to remove file-sharing exposure
sudo systemctl disable --now nfs-server
Disable Samba (SMB) services
sudo systemctl disable --now smb nmb
Disable insecure remote access services (Telnet)
sudo systemctl disable --now xinetd telnet rsh
Show services enabled at startup and identify anything suspicious
systemctl list-unit-files --type=service | grep enabled

Minutes 31–40: Credential & Protocol Hardening
Configure SSH to disable weak ciphers
sudo nano /etc/ssh/sshd_config
Reload SSH changes
sudo systemctl restart sshd
Disable systemd DNS resolver when configuring LLMNR/mDNS behavior
sudo systemctl disable --now systemd-resolved

Minutes 41-50: Logging, Auditing & Integrity
Ensure auditd is running and starts on boot
sudo systemctl enable --now auditd
List current audit rules and check if all rules are applied
sudo auditctl -l
Add custom hardening rules to /etc/audit/rules.d/hardening.rules
-w /etc/passwd -p wa -k passwd_changes (Log write/append changes to /etc/passwd)
-w /etc/shadow -p wa -k shadow_changes (Log write/append changes to /etc/shadow)
-w /var/log/ -p wa -k log_changes (Watch for unauthorized changes to log files)
-a always,exit -F arch=b64 -S execve -k exec_log (Log all commands)
Compile and load audit rules from /etc/audit/rules.d
sudo augenrules --load

Minutes 51–55: Allow-List Rules Only
Only allow SSH from the jump box (10.0.5.10)
sudo firewall-cmd --add-rich-rule="rule family='ipv4' \
source address='10.0.5.10' port port='22' protocWindowsPlaybookol='tcp' accept"
Verify no broad or accidental allow rules
sudo firewall-cmd --list-all

Minutes 56-60: Verifications, Snapshots, Evidence
Final firewall verifications
sudo firewall-cmd --list-all
Display status of auditd and loaded rules
sudo auditctl -s
Confirm disabled services are inactive
sudo systemctl status <service>
Backup all system configurations
sudo cp -r /etc /root/etc-backup-$(date +%F)
Display important logs and errors for evidence
journalctl -xe





Web ServerWindowsPlaybook



Database
1–10: FIREWALL TO DEFAULT DENY + LOGGING
1. Enable firewall
UFW (Ubuntu/Debian)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging on
sudo ufw enable
Firewalld (RHEL/CentOS/Rocky)
sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --zone=drop --set-target=DROP
sudo firewall-cmd --set-log-denied=all
sudo firewall-cmd --reload

2. Ensure firewall profiles/zones active
sudo ufw status verbose
# or
sudo firewall-cmd --get-active-zones

3. Log size ≥ 16MB
sudo sed -i 's/rotate [0-9]*/rotate 4/' /etc/logrotate.d/ufw
sudo sed -i 's/size [0-9]*k/size 16384k/' /etc/logrotate.d/ufw

**4. Add only explicit inbound allows after lockdown
Example for a PostgreSQL DB server only accessible from jump box 10.0.0.5:
sudo ufw allow from 10.0.0.5 to any port 5432

or firewalld:
sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.0.0.5" port protocol="tcp" port="5432" accept'
sudo firewall-cmd --runtime-to-permanent


11–20: ACCOUNTS, PASSWORDS, LOCKOUTS
5. Password settings (CIS L1)
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN     14/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

6. Enforce password complexity & history
(Using PAM pam_pwquality + pam_pwhistory)
sudo sed -i'/pam_pwqual ity.so/ s/$/ retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/' /etc/pam.d/common-password
echo "password required pam_pwhistory.so remember=5 use_authtok" | sudo tee -a /etc/pam.d/common-password

7. Account lockout threshold
echo "auth required pam_faillock.so deny=5 unlock_time=900 even_deny_root" | sudo tee -a /etc/pam.d/common-auth

8. Disable guest access
Ubuntu:
sudo bash -c 'echo AllowGuest=no >> /etc/lightdm/lightdm.conf'

9. Rename or disable default accounts (if present)
Typical Linux has no “guest/admin”, but disable any unexpected:
sudo usermod -L guest 2>/dev/null
sudo usermod -L admin 2>/dev/null


21–30: KILL THE PIVOTS (Spooler/SMBv1/Autorun equivalents)
Linux doesn’t have Windows Print Spooler/SMBv1/Autorun, but kill equivalent pivot services:
10. Disable CUPS (print service)
sudo systemctl stop cups
sudo systemctl disable cups

11. Disable Samba if not required
sudo systemctl stop smb nmb
sudo systemctl disable smb nmb

12. Disable USB auto-mounting
sudo apt-get install usbguard -y 2>/dev/null
sudo systemctl enable --now usbguard


31–40: CREDENTIAL & PROTOCOL HARDENING (LSA/NTLM/LLMNR equivalents)
13. Disable LLMNR (systemd-resolved)
sudo sed -i 's/^LLMNR=.*/LLMNR=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

14. Disable multicast DNS (mDNS)
sudo sed -i 's/^MulticastDNS=.*/MulticastDNS=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved

15. Disable IPv6 if policy allows (common in CCDC)
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

16. Harden SSH (equivalent to NTLMv2-only + LSA protections)
Block interactive login 
Only want interactive login from jump server
Edit:
sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
sudo systemctl restart sshd


41–50: ADVANCED AUDITING
17. Enable auditd
sudo apt install auditd audispd-plugins -y
sudo systemctl enable --now auditd

18. Force subcategories
Linux equivalent = enable full audit rules.
19. Add CIS L1 audit rules
sudo tee /etc/audit/rules.d/custom.rules <<EOF
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes

-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

-w /var/log/ -p wa -k log_modifications
-w /etc/ssh/sshd_config -p wa -k ssh_config
EOF

sudo augenrules --load

20. Audit login/logoff & authentication
sudo sed -i 's/^log_format.*/log_format = ENRICHED/' /etc/audit/auditd.conf
sudo systemctl restart auditd


51–55: ALLOW-LIST ONLY (Minimal inbound)
21. Remove all broad/firewall "any" rules
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging on

22. Allow inbound only from jump box
Example:
sudo ufw allow from 10.0.0.5 to any port 22 proto tcp
sudo ufw allow from 10.0.0.5 to any port 5432 proto tcp

23. Absolutely no allow any or wide ranges
Verify:
sudo ufw status numbered


56–60: VERIFY, SNAPSHOT, EVIDENCE
24. Verify auditing
sudo auditctl -l
sudo auditctl -s

25. Verify firewall
sudo ufw status verbose
# or
sudo firewall-cmd --list-all

26. Verify pivot services disabled
systemctl status cups
systemctl status smb nmb

27. Verify SSH hardening
sshd -T | grep -E 'passwordauthentication|maxauthtries|permitrootlogin|loglevel'

28. Snapshot configs
sudo cp /etc/ssh/sshd_config /root/ssh_config.snapshot
sudo cp /etc/audit/audit.rules /root/audit.rules.snapshot 2>/dev/null
sudo ufw status verbose > /root/ufw.snapshot

29. Export security policy (Linux equivalent)
sudo tar -cvf /root/security-configs.tar /etc/ssh /etc/audit /etc/ufw /etc/systemd/resolved.conf

30. Final evidence bundle
hostnamectl > /root/evidence.txt sudo journalctl -b >> /root/evidence.txt

EXTRA COMMANDS

MySQL/MariaDB Commands (with comments) sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
Set bind-address to 127.0.0.1 or internal-only IP to block external access.
sudo mysql_secure_installation
Removes test users, test DB, and enforces secure defaults.
Restrict privileges for the app user
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'appuser'@'10.0.5.20';
Gives only required permissions to the web server.
FLUSH PRIVILEGES;
Applies privilege changes.
sudo chmod 700 /var/lib/mysql
Restricts DB data directory access.
PostgreSQL Commands (with comments) sudo nano /etc/postgresql//main/postgresql.conf
Set 'listen_addresses' to internal IP only.
sudo nano /etc/postgresql//main/pg_hba.conf
Restrict access to specific IPs with md5 auth.
sudo chmod 700 /var/lib/postgresql
Locks down database directory.
Database Firewall Rules (with comments) MySQL/MariaDB (3306) sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='10.0.5.30' port port='3306' protocol='tcp' accept"
Only allow MySQL traffic from the web server IP (10.0.5.30).
PostgreSQL (5432) sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='10.0.5.30' port port='5432' protocol='tcp' accept"
Only allow PostgreSQL traffic from the web server IP.
