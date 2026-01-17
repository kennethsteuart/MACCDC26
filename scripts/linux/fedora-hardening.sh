#!/bin/bash
################################################################################
# Fedora/RHEL-family System Hardening Script (Blue Team Competition Edition)
# Usage: sudo ./harden_fedora.sh
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="/var/log/hardening_${TIMESTAMP}.log"
BACKUP_DIR="/root/hardening_backup_${TIMESTAMP}"
EVIDENCE_DIR="/root/evidence_${TIMESTAMP}"

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}This script must be run as root${NC}"
  exit 1
fi

log(){ echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"; }
warn(){ echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOGFILE"; }
section(){
  echo -e "\n${CYAN}========================================${NC}"
  echo -e "${CYAN}$1${NC}"
  echo -e "${CYAN}========================================${NC}\n"
}

pre_flight() {
  section "PRE-FLIGHT: Initial Setup and Backups"
  mkdir -p "$BACKUP_DIR" "$EVIDENCE_DIR"

  log "Backup directory: $BACKUP_DIR"
  log "Evidence directory: $EVIDENCE_DIR"

  log "Creating backups of critical configuration files..."
  cp /etc/passwd "$BACKUP_DIR/passwd.bak"
  cp /etc/shadow "$BACKUP_DIR/shadow.bak"
  cp /etc/group  "$BACKUP_DIR/group.bak"
  cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
  cp /etc/sudoers "$BACKUP_DIR/sudoers.bak" 2>/dev/null
  cp /etc/login.defs "$BACKUP_DIR/login.defs.bak"

  log "Current wheel group members:"
  grep -E '^wheel:' /etc/group | tee -a "$EVIDENCE_DIR/sudo_users.txt"

  log "Updating system packages..."
  dnf -y update >>"$LOGFILE" 2>&1

  log "Pre-flight tasks completed"
}

configure_firewall() {
  section "MINUTES 1-10: Firewall Baseline (Default Deny) [firewalld]"

  log "Enabling firewalld..."
  dnf -y install firewalld >>"$LOGFILE" 2>&1 || true
  systemctl enable --now firewalld

  # Note: setting default zone to drop is aggressive; matches your intent.
  firewall-cmd --set-default-zone=drop
  firewall-cmd --zone=drop --set-target=DROP
  firewall-cmd --set-log-denied=all
  firewall-cmd --reload

  log "Firewall configuration:"
  firewall-cmd --list-all | tee -a "$EVIDENCE_DIR/firewall_config.txt"
}

harden_accounts() {
  section "MINUTES 11-20: Accounts, Passwords, and Lockouts"

  log "Configuring password age policies..."
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'  /etc/login.defs
  sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/'  /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/'  /etc/login.defs

  log "Enforcing password complexity (pwquality)..."
  dnf -y install libpwquality pam >>"$LOGFILE" 2>&1 || true
  if [ -f /etc/security/pwquality.conf ]; then
    cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.bak"
    cat >> /etc/security/pwquality.conf << 'EOF'

# Password complexity requirements
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF
  fi

  log "Configuring password history / lockouts via authselect (preferred on Fedora/RHEL)..."
  # authselect manages PAM templates; direct edits can be overwritten.
  if command -v authselect &>/dev/null; then
    # enable faillock and pwhistory features if available
    authselect current | tee -a "$EVIDENCE_DIR/authselect_current.txt" 2>/dev/null || true
    authselect enable-feature with-faillock 2>/dev/null || true
    authselect enable-feature with-pwhistory 2>/dev/null || true
    authselect apply-changes 2>/dev/null || true
  else
    warn "authselect not found. Falling back to direct PAM edits."
    if [ -f /etc/pam.d/system-auth ]; then
      cp /etc/pam.d/system-auth "$BACKUP_DIR/system-auth.bak"
      grep -q "pam_pwhistory.so" /etc/pam.d/system-auth || echo "password required pam_pwhistory.so remember=5 use_authtok" >> /etc/pam.d/system-auth
      grep -q "pam_faillock.so"  /etc/pam.d/system-auth || sed -i '/^auth.*pam_unix.so/i auth required pam_faillock.so preauth deny=5 unlock_time=900' /etc/pam.d/system-auth
    fi
    if [ -f /etc/pam.d/password-auth ]; then
      cp /etc/pam.d/password-auth "$BACKUP_DIR/password-auth.bak"
      grep -q "pam_faillock.so" /etc/pam.d/password-auth || sed -i '/^auth.*pam_unix.so/i auth required pam_faillock.so preauth deny=5 unlock_time=900' /etc/pam.d/password-auth
    fi
  fi

  log "Locking guest and admin accounts (if present)..."
  usermod -L guest 2>/dev/null && log "Locked guest account" || warn "Guest account not found"
  usermod -L admin 2>/dev/null && log "Locked admin account" || warn "Admin account not found"

  log "Removing shell access for common system accounts..."
  for user in daemon bin sys sync games man lp mail news uucp proxy backup list irc nobody; do
    if id "$user" &>/dev/null; then
      usermod -s /sbin/nologin "$user" 2>/dev/null
    fi
  done

  log "Account hardening completed"
}

disable_pivot_services() {
  section "MINUTES 21-30: Disable Pivots & Lateral Movement Services"

  SERVICES_TO_DISABLE=(
    "cups" "cups-browsed"
    "avahi-daemon"
    "nfs-server"
    "smb" "nmb" "smbd" "nmbd"
    "xinetd"
    "telnet"
    "rsh" "rlogin"
  )

  for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      systemctl stop "$service"
      systemctl disable "$service"
      log "Disabled service: $service"
    fi
  done

  log "Installing and configuring USBGuard..."
  dnf -y install usbguard >>"$LOGFILE" 2>&1 || true
  if command -v usbguard &>/dev/null; then
    systemctl enable --now usbguard 2>/dev/null
    log "USBGuard enabled"
  fi

  log "Enabled services at startup:"
  systemctl list-unit-files --type=service | grep enabled | tee -a "$EVIDENCE_DIR/enabled_services.txt"
}

harden_protocols() {
  section "MINUTES 31-40: Credential & Protocol Hardening"

  log "Hardening SSH..."
  cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.pre_ssh_hardening.bak"

  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
  sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
  sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

  grep -q "^Protocol 2" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config

  cat >> /etc/ssh/sshd_config << 'EOF'

# Strong ciphers only
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms diffie-hellman-group-exchange-sha256
EOF

  systemctl restart sshd
  log "SSH hardened and restarted"

  log "Disabling LLMNR/mDNS (systemd-resolved if present)..."
  if [ -f /etc/systemd/resolved.conf ]; then
    cp /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.bak"
    sed -i 's/^#\?LLMNR=.*/LLMNR=no/' /etc/systemd/resolved.conf
    sed -i 's/^#\?MulticastDNS=.*/MulticastDNS=no/' /etc/systemd/resolved.conf
    systemctl restart systemd-resolved 2>/dev/null || true
  fi

  read -p "Disable systemd-resolved completely? (y/n): " -n 1 -r; echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl disable --now systemd-resolved
    log "systemd-resolved disabled"
  fi

  read -p "Disable IPv6? (y/n): " -n 1 -r; echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Disabling IPv6..."
    cat >> /etc/sysctl.conf << 'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    sysctl -p
    log "IPv6 disabled"
  fi
}

configure_auditing() {
  section "MINUTES 41-50: Logging, Auditing & Integrity"

  log "Installing audit..."
  dnf -y install audit audispd-plugins >>"$LOGFILE" 2>&1
  systemctl enable --now auditd

  if [ -f /etc/audit/auditd.conf ]; then
    cp /etc/audit/auditd.conf "$BACKUP_DIR/auditd.conf.bak"
    sed -i 's/^log_format.*/log_format = ENRICHED/' /etc/audit/auditd.conf
    systemctl restart auditd
  fi

  log "Adding audit rules..."
  cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes
-w /etc/security/opasswd -p wa -k password_history
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /var/log/ -p wa -k log_changes
-w /var/log/secure -p wa -k secure_log
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log
-w /etc/hosts -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config
-w /etc/rc.local -p wa -k init_scripts
-w /bin/systemctl -p x -k systemd
-w /etc/systemd/ -p wa -k systemd
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/login.defs -p wa -k login_config
-w /etc/securetty -p wa -k login_config
-w /var/log/faillog -p wa -k login_failures
-w /var/log/lastlog -p wa -k last_logins
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-e 2
EOF

  augenrules --load
  log "Current audit rules:"
  auditctl -l | tee -a "$EVIDENCE_DIR/audit_rules.txt"
  log "Audit status:"
  auditctl -s | tee -a "$EVIDENCE_DIR/audit_status.txt"
}

configure_allowlist() {
  section "MINUTES 51-55: Allow-List Rules Only (Minimal Inbound)"
  warn "firewalld default zone is DROP. Add only what you need."

  read -p "Enter Jump Box IP address (e.g., 10.0.5.10): " JUMP_IP
  [ -z "$JUMP_IP" ] && warn "No jump box IP provided - skipping allow rules" && return

  log "Allowing SSH from jump box: $JUMP_IP"
  firewall-cmd --add-rich-rule="rule family='ipv4' source address='$JUMP_IP' port port='22' protocol='tcp' accept"
  firewall-cmd --runtime-to-permanent

  read -p "Is this a database server? (y/n): " -n 1 -r; echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Database type (mysql/postgres): " DB_TYPE
    read -p "Enter application server IP: " APP_IP
    if [ "$DB_TYPE" == "mysql" ]; then
      firewall-cmd --add-rich-rule="rule family='ipv4' source address='$APP_IP' port port='3306' protocol='tcp' accept"
      log "Added MySQL allow rule for $APP_IP"
    elif [ "$DB_TYPE" == "postgres" ]; then
      firewall-cmd --add-rich-rule="rule family='ipv4' source address='$APP_IP' port port='5432' protocol='tcp' accept"
      log "Added PostgreSQL allow rule for $APP_IP"
    fi
    firewall-cmd --runtime-to-permanent
  fi

  log "Final firewall configuration:"
  firewall-cmd --list-all | tee -a "$EVIDENCE_DIR/final_firewall.txt"
  warn "Verify no broad 'any' rules exist!"
}

harden_database() {
  section "DATABASE HARDENING (Optional)"
  read -p "Is this a database server? (y/n): " -n 1 -r; echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && return

  read -p "Database type (mysql/postgres): " DB_TYPE

  if [ "$DB_TYPE" == "mysql" ]; then
    log "Hardening MySQL/MariaDB..."
    MYSQL_CONF="/etc/my.cnf"
    if [ -f "$MYSQL_CONF" ]; then
      cp "$MYSQL_CONF" "$BACKUP_DIR/my.cnf.bak"
      read -p "Enter MySQL bind address (127.0.0.1 or internal IP): " BIND_ADDR
      if ! grep -q "^bind-address" "$MYSQL_CONF"; then
        echo "bind-address = $BIND_ADDR" >> "$MYSQL_CONF"
      else
        sed -i "s/^bind-address.*/bind-address = $BIND_ADDR/" "$MYSQL_CONF"
      fi
      systemctl restart mysqld 2>/dev/null || systemctl restart mariadb 2>/dev/null
    else
      warn "MySQL config not found at /etc/my.cnf. Review your distro's MariaDB layout."
    fi
    chmod 700 /var/lib/mysql 2>/dev/null
    warn "Run 'mysql_secure_installation' manually to complete MySQL hardening"

  elif [ "$DB_TYPE" == "postgres" ]; then
    log "Hardening PostgreSQL..."
    # Fedora/RHEL typically uses /var/lib/pgsql/data; config is usually there.
    PG_CONF="/var/lib/pgsql/data/postgresql.conf"
    PG_HBA="/var/lib/pgsql/data/pg_hba.conf"

    if [ -f "$PG_CONF" ]; then
      cp "$PG_CONF" "$BACKUP_DIR/postgresql.conf.bak"
      read -p "Enter PostgreSQL listen address (127.0.0.1 or internal IP): " LISTEN_ADDR
      sed -i "s/^#\?listen_addresses.*/listen_addresses = '$LISTEN_ADDR'/" "$PG_CONF"
    else
      warn "PostgreSQL config not found at $PG_CONF. Adjust path if using a different PG version/layout."
    fi

    if [ -f "$PG_HBA" ]; then
      cp "$PG_HBA" "$BACKUP_DIR/pg_hba.conf.bak"
      warn "Review $PG_HBA manually to restrict access to specific IPs with scram-sha-256"
    fi

    chmod 700 /var/lib/pgsql 2>/dev/null
    systemctl restart postgresql 2>/dev/null
  fi
}

create_evidence() {
  section "MINUTES 56-60: Verifications, Snapshots, and Evidence"

  log "Final firewall verification:"
  firewall-cmd --list-all | tee -a "$EVIDENCE_DIR/firewall_final.txt"

  log "Audit verification:"
  auditctl -l | tee -a "$EVIDENCE_DIR/audit_final.txt"
  auditctl -s | tee -a "$EVIDENCE_DIR/audit_status_final.txt"

  log "Service verification:"
  for service in cups smbd nmbd avahi-daemon; do
    systemctl status "$service" 2>/dev/null | grep -E "Active|Loaded" | tee -a "$EVIDENCE_DIR/services_status.txt"
  done

  log "SSH verification:"
  sshd -T | grep -E 'passwordauthentication|maxauthtries|permitrootlogin|loglevel' | tee -a "$EVIDENCE_DIR/ssh_config.txt"

  log "Creating configuration snapshots..."
  cp /etc/ssh/sshd_config "$EVIDENCE_DIR/sshd_config.snapshot"
  cp /etc/audit/audit.rules "$EVIDENCE_DIR/audit.rules.snapshot" 2>/dev/null

  log "Creating security configuration archive..."
  tar -czf "$EVIDENCE_DIR/security-configs.tar.gz" \
    /etc/ssh /etc/audit /etc/systemd/resolved.conf /etc/login.defs /etc/security/pwquality.conf \
    2>/dev/null

  log "Backing up entire /etc directory..."
  cp -r /etc "$BACKUP_DIR/etc-backup-$(date +%F)"

  log "Creating evidence bundle..."
  {
    echo "========================================="
    echo "SYSTEM HARDENING EVIDENCE"
    echo "Generated: $(date)"
    echo "========================================="
    echo ""
    hostnamectl
    echo ""
    echo "========================================="
    echo "FIREWALL STATUS"
    echo "========================================="
    firewall-cmd --list-all
    echo ""
    echo "========================================="
    echo "AUDIT STATUS"
    echo "========================================="
    auditctl -s
    echo ""
    echo "========================================="
    echo "ENABLED SERVICES"
    echo "========================================="
    systemctl list-unit-files --type=service | grep enabled
    echo ""
    echo "========================================="
    echo "WHEEL USERS"
    echo "========================================="
    grep -E '^wheel:' /etc/group
    echo ""
    echo "========================================="
    echo "RECENT JOURNAL ENTRIES"
    echo "========================================="
    journalctl -b -n 100
  } > "$EVIDENCE_DIR/evidence.txt"

  log "Recent critical log entries:"
  journalctl -xe -n 50 | tee -a "$EVIDENCE_DIR/recent_logs.txt"
}

main() {
  clear
  echo -e "${CYAN}"
  cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     FEDORA/RHEL SYSTEM HARDENING SCRIPT                    ║
║     Blue Team Competition Edition                          ║
║     60-Minute Hardening Timeline                           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
  echo -e "${NC}"

  log "========================================="
  log "Starting Fedora/RHEL System Hardening"
  log "========================================="

  pre_flight
  configure_firewall
  harden_accounts
  disable_pivot_services
  harden_protocols
  configure_auditing
  configure_allowlist
  harden_database
  create_evidence

  section "HARDENING COMPLETE!"
  echo -e "${YELLOW}Backup Directory:${NC} $BACKUP_DIR"
  echo -e "${YELLOW}Evidence Directory:${NC} $EVIDENCE_DIR"
  echo -e "${YELLOW}Log File:${NC} $LOGFILE"
  echo -e "${RED}CRITICAL: Test SSH in a NEW terminal before closing this session!${NC}"

  read -p "Press Enter to view evidence summary..."
  cat "$EVIDENCE_DIR/evidence.txt"
  log "Hardening script completed successfully"
}

main
