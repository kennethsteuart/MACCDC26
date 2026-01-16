# Linux & Server Hardening Playbook

## General Pre-Tasks

* Identify all necessary SSH users
* Enforce least privilege (no unnecessary sudoers)

```bash
grep -E 'sudo|wheel' /etc/group
```

* Disable root SSH login

```bash
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

* Update all system packages

```bash
# Debian/Ubuntu
sudo apt update && sudo apt upgrade -y

# Fedora/RHEL
sudo dnf update -y
```

---

## Minutes 1–10: Firewall Baseline (Default Deny)

```bash
sudo systemctl enable --now firewalld
sudo firewall-cmd --set-default-zone=public
sudo firewall-cmd --zone=public --set-target=DROP
sudo firewall-cmd --set-log-denied=all
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

---

## Minutes 11–20: Accounts, Passwords, Lockouts

* Edit password complexity

```bash
sudo nano /etc/security/pwquality.conf
```

* Edit password aging

```bash
sudo nano /etc/login.defs
```

* Configure lockout policies

```bash
sudo nano /etc/pam.d/system-auth
sudo nano /etc/pam.d/password-auth
```

* Lock unnecessary accounts

```bash
sudo usermod -L username
sudo usermod -s /sbin/nologin account
```

---

## Minutes 21–30: Disable Pivots & Lateral Movement

```bash
sudo systemctl disable --now cups
sudo systemctl disable --now avahi-daemon
sudo systemctl disable --now nfs-server
sudo systemctl disable --now smb nmb
sudo systemctl disable --now xinetd telnet rsh
systemctl list-unit-files --type=service | grep enabled
```

---

## Minutes 31–40: Credential & Protocol Hardening

```bash
sudo nano /etc/ssh/sshd_config
sudo systemctl restart sshd
sudo systemctl disable --now systemd-resolved
```

---

## Minutes 41–50: Logging, Auditing & Integrity

```bash
sudo systemctl enable --now auditd
sudo auditctl -l
```

### Audit Rules

```bash
sudo nano /etc/audit/rules.d/hardening.rules
```

```text
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /var/log/ -p wa -k log_changes
-a always,exit -F arch=b64 -S execve -k exec_log
```

```bash
sudo augenrules --load
```

---

## Minutes 51–55: Allow-List Rules Only

```bash
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='10.0.5.10' port port='22' protocol='tcp' accept"
sudo firewall-cmd --list-all
```

---

## Minutes 56–60: Verification & Evidence

```bash
sudo firewall-cmd --list-all
sudo auditctl -s
sudo systemctl status <service>
sudo cp -r /etc /root/etc-backup-$(date +%F)
journalctl -xe
```

---

# Web / Database Server Hardening

## Firewall (Default Deny)

### UFW (Ubuntu/Debian)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging on
sudo ufw enable
```

### Firewalld (RHEL-based)

```bash
sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --zone=drop --set-target=DROP
sudo firewall-cmd --set-log-denied=all
sudo firewall-cmd --reload
```

---

## Password & Account Policy (CIS L1)

```bash
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN     14/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
```

---

## SSH Hardening

```bash
sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## Database Hardening

### MySQL / MariaDB

```bash
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
sudo mysql_secure_installation
```

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'appuser'@'10.0.5.20';
FLUSH PRIVILEGES;
```

```bash
sudo chmod 700 /var/lib/mysql
```

### PostgreSQL

```bash
sudo nano /etc/postgresql/*/main/postgresql.conf
sudo nano /etc/postgresql/*/main/pg_hba.conf
sudo chmod 700 /var/lib/postgresql
```

---

## Database Firewall Rules

```bash
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='10.0.5.30' port port='3306' protocol='tcp' accept"
sudo firewall-cmd --add-rich-rule="rule family='ipv4' source address='10.0.5.30' port port='5432' protocol='tcp' accept"
```
