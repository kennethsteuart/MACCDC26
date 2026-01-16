#!/bin/bash
################################################################################
# Linux System Hardening Script for Blue Team Competition
# Purpose: CCDC/Red Team vs Blue Team rapid system hardening
# Usage: sudo ./linux_hardening.sh
# Based on 60-minute hardening timeline
################################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Log file and backup directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="/var/log/hardening_${TIMESTAMP}.log"
BACKUP_DIR="/root/hardening_backup_${TIMESTAMP}"
EVIDENCE_DIR="/root/evidence_${TIMESTAMP}"

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    OS=$(uname -s)
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOGFILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOGFILE"
}

section() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}\n"
}

################################################################################
# PRE-FLIGHT TASKS
################################################################################
pre_flight() {
    section "PRE-FLIGHT: Initial Setup and Backups"
    
    # Create directories
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$EVIDENCE_DIR"
    
    log "Backup directory: $BACKUP_DIR"
    log "Evidence directory: $EVIDENCE_DIR"
    
    # Backup critical files
    log "Creating backups of critical configuration files..."
    cp /etc/passwd "$BACKUP_DIR/passwd.bak"
    cp /etc/shadow "$BACKUP_DIR/shadow.bak"
    cp /etc/group "$BACKUP_DIR/group.bak"
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
    cp /etc/sudoers "$BACKUP_DIR/sudoers.bak" 2>/dev/null
    cp /etc/login.defs "$BACKUP_DIR/login.defs.bak"
    
    # Identify sudo users
    log "Current sudo/wheel group members:"
    grep -E 'sudo|wheel' /etc/group | tee -a "$EVIDENCE_DIR/sudo_users.txt"
    
    # Update system packages
    log "Updating system packages..."
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt update && apt upgrade -y >> "$LOGFILE" 2>&1
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        dnf update -y >> "$LOGFILE" 2>&1
    fi
    
    log "Pre-flight tasks completed"
}

################################################################################
# MINUTES 1-10: FIREWALL BASELINE (DEFAULT DENY)
################################################################################
configure_firewall() {
    section "MINUTES 1-10: Firewall Baseline (Default Deny)"
    
    # Detect and configure appropriate firewall
    if command -v firewall-cmd &> /dev/null; then
        log "Configuring firewalld..."
        
        # Enable firewalld
        systemctl enable --now firewalld
        
        # Set default zone to drop
        firewall-cmd --set-default-zone=drop
        
        # Set target to DROP for drop zone
        firewall-cmd --zone=drop --set-target=DROP
        
        # Enable logging of denied packets
        firewall-cmd --set-log-denied=all
        
        # Reload firewall
        firewall-cmd --reload
        
        # Verify settings
        log "Firewall configuration:"
        firewall-cmd --list-all | tee -a "$EVIDENCE_DIR/firewall_config.txt"
        
    elif command -v ufw &> /dev/null; then
        log "Configuring UFW..."
        
        # Reset UFW to clean state
        ufw --force reset
        
        # Set default policies
        ufw default deny incoming
        ufw default allow outgoing
        
        # Enable logging
        ufw logging on
        
        # Configure log rotation (16MB minimum)
        if [ -f /etc/logrotate.d/ufw ]; then
            sed -i 's/rotate [0-9]*/rotate 4/' /etc/logrotate.d/ufw
            sed -i 's/size [0-9]*k/size 16384k/' /etc/logrotate.d/ufw
        fi
        
        # Enable UFW
        ufw --force enable
        
        # Verify settings
        log "Firewall configuration:"
        ufw status verbose | tee -a "$EVIDENCE_DIR/firewall_config.txt"
        
    else
        # Install UFW if neither is available
        log "Installing UFW..."
        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
            apt-get install -y ufw
        else
            warn "No firewall found and unable to install. Manual configuration required."
            return
        fi
        configure_firewall
    fi
}

################################################################################
# MINUTES 11-20: ACCOUNTS, PASSWORDS, LOCKOUTS
################################################################################
harden_accounts() {
    section "MINUTES 11-20: Accounts, Passwords, and Lockouts"
    
    # Password age settings
    log "Configuring password age policies..."
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    
    # Password complexity (pwquality)
    log "Enforcing password complexity..."
    if [ -f /etc/security/pwquality.conf ]; then
        cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.bak"
        cat >> /etc/security/pwquality.conf << EOF
# Password complexity requirements
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF
    fi
    
    # Configure PAM for password history and complexity
    log "Configuring PAM authentication..."
    if [ -f /etc/pam.d/common-password ]; then
        # Ubuntu/Debian
        if ! grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
            echo "password required pam_pwhistory.so remember=5 use_authtok" >> /etc/pam.d/common-password
        fi
    elif [ -f /etc/pam.d/system-auth ]; then
        # RHEL/CentOS
        if ! grep -q "pam_pwhistory.so" /etc/pam.d/system-auth; then
            echo "password required pam_pwhistory.so remember=5 use_authtok" >> /etc/pam.d/system-auth
        fi
    fi
    
    # Account lockout policies
    log "Configuring account lockout policies..."
    if [ -f /etc/pam.d/common-auth ]; then
        if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
            echo "auth required pam_faillock.so deny=5 unlock_time=900 even_deny_root" >> /etc/pam.d/common-auth
        fi
    fi
    
    if [ -f /etc/pam.d/system-auth ]; then
        cp /etc/pam.d/system-auth "$BACKUP_DIR/system-auth.bak"
        if ! grep -q "pam_faillock.so" /etc/pam.d/system-auth; then
            sed -i '/^auth.*pam_unix.so/i auth required pam_faillock.so preauth deny=5 unlock_time=900' /etc/pam.d/system-auth
        fi
    fi
    
    # Lock unnecessary accounts
    log "Locking guest and admin accounts..."
    usermod -L guest 2>/dev/null && log "Locked guest account" || warn "Guest account not found"
    usermod -L admin 2>/dev/null && log "Locked admin account" || warn "Admin account not found"
    
    # Remove shell access for system accounts
    log "Removing shell access for system accounts..."
    for user in daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
        if id "$user" &>/dev/null; then
            usermod -s /sbin/nologin "$user" 2>/dev/null
        fi
    done
    
    # Disable guest access (Ubuntu)
    if [ -f /etc/lightdm/lightdm.conf ]; then
        if ! grep -q "AllowGuest=no" /etc/lightdm/lightdm.conf; then
            echo "AllowGuest=no" >> /etc/lightdm/lightdm.conf
        fi
    fi
    
    log "Account hardening completed"
}

################################################################################
# MINUTES 21-30: DISABLE PIVOTS & LATERAL MOVEMENT SERVICES
################################################################################
disable_pivot_services() {
    section "MINUTES 21-30: Disable Pivots & Lateral Movement Services"
    
    SERVICES_TO_DISABLE=(
        "cups"                  # Print service
        "cups-browsed"          # Print service
        "avahi-daemon"          # mDNS/LLMNR (name spoofing)
        "nfs-server"            # NFS server
        "nfs-client"            # NFS client
        "smb"                   # Samba SMB
        "nmb"                   # Samba NetBIOS
        "smbd"                  # Samba daemon
        "nmbd"                  # NetBIOS daemon
        "xinetd"                # Super-server daemon
        "telnet"                # Telnet server
        "rsh"                   # Remote shell
        "rlogin"                # Remote login
    )
    
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service"
            systemctl disable "$service"
            log "Disabled service: $service"
        fi
    done
    
    # Install and enable usbguard (disable USB auto-mounting)
    log "Installing and configuring USBGuard..."
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y usbguard 2>/dev/null
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]]; then
        dnf install -y usbguard 2>/dev/null
    fi
    
    if command -v usbguard &> /dev/null; then
        systemctl enable --now usbguard 2>/dev/null
        log "USBGuard enabled"
    fi
    
    # List all enabled services for review
    log "Enabled services at startup:"
    systemctl list-unit-files --type=service | grep enabled | tee -a "$EVIDENCE_DIR/enabled_services.txt"
}

################################################################################
# MINUTES 31-40: CREDENTIAL & PROTOCOL HARDENING
################################################################################
harden_protocols() {
    section "MINUTES 31-40: Credential & Protocol Hardening"
    
    # Disable root SSH login
    log "Disabling root SSH login..."
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Disable password authentication (key-based only)
    log "Configuring SSH for key-based authentication only..."
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Set max authentication tries
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    
    # Enable verbose logging
    sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    
    # Disable X11 forwarding
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    
    # Disable empty passwords
    sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    
    # Set protocol 2 only
    if ! grep -q "^Protocol 2" /etc/ssh/sshd_config; then
        echo "Protocol 2" >> /etc/ssh/sshd_config
    fi
    
    # Disable weak ciphers and enable strong ones
    cat >> /etc/ssh/sshd_config << 'EOF'

# Strong ciphers only
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms diffie-hellman-group-exchange-sha256
EOF
    
    # Restart SSH
    systemctl restart sshd
    log "SSH hardened and restarted"
    
    # Disable LLMNR (systemd-resolved)
    log "Disabling LLMNR..."
    if [ -f /etc/systemd/resolved.conf ]; then
        cp /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.bak"
        sed -i 's/^#\?LLMNR=.*/LLMNR=no/' /etc/systemd/resolved.conf
        sed -i 's/^#\?MulticastDNS=.*/MulticastDNS=no/' /etc/systemd/resolved.conf
        systemctl restart systemd-resolved 2>/dev/null
    fi
    
    # Disable systemd-resolved if not needed
    read -p "Disable systemd-resolved completely? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl disable --now systemd-resolved
        log "systemd-resolved disabled"
    fi
    
    # Disable IPv6 if not needed
    read -p "Disable IPv6? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Disabling IPv6..."
        cat >> /etc/sysctl.conf << EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        sysctl -p
        log "IPv6 disabled"
    fi
}

################################################################################
# MINUTES 41-50: LOGGING, AUDITING & INTEGRITY
################################################################################
configure_auditing() {
    section "MINUTES 41-50: Logging, Auditing & Integrity"
    
    # Install auditd
    log "Installing and configuring auditd..."
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y auditd audispd-plugins
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        dnf install -y audit audispd-plugins
    fi
    
    # Enable and start auditd
    systemctl enable --now auditd
    
    # Configure audit log format
    if [ -f /etc/audit/auditd.conf ]; then
        cp /etc/audit/auditd.conf "$BACKUP_DIR/auditd.conf.bak"
        sed -i 's/^log_format.*/log_format = ENRICHED/' /etc/audit/auditd.conf
        systemctl restart auditd
    fi
    
    # Add comprehensive audit rules
    log "Adding CIS Level 1 audit rules..."
    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (0=silent 1=printk 2=panic)
-f 1

# Password and authentication changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes
-w /etc/security/opasswd -p wa -k password_history

# System and sudo changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Log file modifications
-w /var/log/ -p wa -k log_changes
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/secure -p wa -k secure_log

# Process execution tracking
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

# Network configuration changes
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config

# System startup scripts
-w /etc/rc.local -p wa -k init_scripts

# Library search paths
-w /etc/ld.so.conf -p wa -k libpath

# Systemd
-w /bin/systemctl -p x -k systemd
-w /etc/systemd/ -p wa -k systemd

# Cron jobs
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron

# User, group, password databases
-w /etc/login.defs -p wa -k login_config
-w /etc/securetty -p wa -k login_config
-w /var/log/faillog -p wa -k login_failures
-w /var/log/lastlog -p wa -k last_logins

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Make configuration immutable
-e 2
EOF
    
    # Load audit rules
    augenrules --load
    
    # Verify audit rules
    log "Current audit rules:"
    auditctl -l | tee -a "$EVIDENCE_DIR/audit_rules.txt"
    
    # Display audit status
    log "Audit system status:"
    auditctl -s | tee -a "$EVIDENCE_DIR/audit_status.txt"
}

################################################################################
# MINUTES 51-55: ALLOW-LIST RULES ONLY
################################################################################
configure_allowlist() {
    section "MINUTES 51-55: Allow-List Rules Only (Minimal Inbound)"
    
    warn "Current firewall configuration should be DEFAULT DENY"
    
    # Prompt for jump box IP
    read -p "Enter Jump Box IP address (e.g., 10.0.5.10): " JUMP_IP
    
    if [ -z "$JUMP_IP" ]; then
        warn "No jump box IP provided - skipping allow rules"
        return
    fi
    
    log "Configuring allow rules for jump box: $JUMP_IP"
    
    if command -v firewall-cmd &> /dev/null; then
        # Firewalld configuration
        log "Adding SSH allow rule for jump box..."
        firewall-cmd --add-rich-rule="rule family='ipv4' source address='$JUMP_IP' port port='22' protocol='tcp' accept"
        firewall-cmd --runtime-to-permanent
        
        # If this is a database server, add database ports
        read -p "Is this a database server? (y/n): " -n 1 -r
        echo
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
        
        # Display final rules
        log "Final firewall configuration:"
        firewall-cmd --list-all | tee -a "$EVIDENCE_DIR/final_firewall.txt"
        
    elif command -v ufw &> /dev/null; then
        # UFW configuration
        log "Adding SSH allow rule for jump box..."
        ufw allow from "$JUMP_IP" to any port 22 proto tcp
        
        # If this is a database server, add database ports
        read -p "Is this a database server? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -p "Database type (mysql/postgres): " DB_TYPE
            read -p "Enter application server IP: " APP_IP
            
            if [ "$DB_TYPE" == "mysql" ]; then
                ufw allow from "$APP_IP" to any port 3306 proto tcp
                log "Added MySQL allow rule for $APP_IP"
            elif [ "$DB_TYPE" == "postgres" ]; then
                ufw allow from "$APP_IP" to any port 5432 proto tcp
                log "Added PostgreSQL allow rule for $APP_IP"
            fi
        fi
        
        # Display final rules
        log "Final firewall configuration:"
        ufw status numbered | tee -a "$EVIDENCE_DIR/final_firewall.txt"
    fi
    
    warn "Verify no broad 'any' rules exist!"
}

################################################################################
# DATABASE SPECIFIC HARDENING (if applicable)
################################################################################
harden_database() {
    section "DATABASE HARDENING (Optional)"
    
    read -p "Is this a database server? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    read -p "Database type (mysql/postgres): " DB_TYPE
    
    if [ "$DB_TYPE" == "mysql" ]; then
        log "Hardening MySQL/MariaDB..."
        
        # MySQL configuration file
        MYSQL_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
        if [ ! -f "$MYSQL_CONF" ]; then
            MYSQL_CONF="/etc/my.cnf"
        fi
        
        if [ -f "$MYSQL_CONF" ]; then
            cp "$MYSQL_CONF" "$BACKUP_DIR/mysqld.cnf.bak"
            
            # Set bind-address to internal only
            read -p "Enter MySQL bind address (127.0.0.1 or internal IP): " BIND_ADDR
            if ! grep -q "^bind-address" "$MYSQL_CONF"; then
                echo "bind-address = $BIND_ADDR" >> "$MYSQL_CONF"
            else
                sed -i "s/^bind-address.*/bind-address = $BIND_ADDR/" "$MYSQL_CONF"
            fi
            
            systemctl restart mysql 2>/dev/null || systemctl restart mariadb 2>/dev/null
        fi
        
        # Secure database directory
        chmod 700 /var/lib/mysql 2>/dev/null
        
        warn "Run 'sudo mysql_secure_installation' manually to complete MySQL hardening"
        
    elif [ "$DB_TYPE" == "postgres" ]; then
        log "Hardening PostgreSQL..."
        
        # Find PostgreSQL config
        PG_CONF=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
        PG_HBA=$(find /etc/postgresql -name "pg_hba.conf" 2>/dev/null | head -1)
        
        if [ -f "$PG_CONF" ]; then
            cp "$PG_CONF" "$BACKUP_DIR/postgresql.conf.bak"
            
            read -p "Enter PostgreSQL listen address (127.0.0.1 or internal IP): " LISTEN_ADDR
            sed -i "s/^#\?listen_addresses.*/listen_addresses = '$LISTEN_ADDR'/" "$PG_CONF"
        fi
        
        if [ -f "$PG_HBA" ]; then
            cp "$PG_HBA" "$BACKUP_DIR/pg_hba.conf.bak"
            warn "Review $PG_HBA manually to restrict access to specific IPs with md5 auth"
        fi
        
        # Secure database directory
        chmod 700 /var/lib/postgresql 2>/dev/null
        
        # Restart PostgreSQL
        systemctl restart postgresql 2>/dev/null
    fi
}

################################################################################
# MINUTES 56-60: VERIFICATIONS, SNAPSHOTS, EVIDENCE
################################################################################
create_evidence() {
    section "MINUTES 56-60: Verifications, Snapshots, and Evidence"
    
    # Firewall verification
    log "Final firewall verification:"
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --list-all | tee -a "$EVIDENCE_DIR/firewall_final.txt"
    elif command -v ufw &> /dev/null; then
        ufw status verbose | tee -a "$EVIDENCE_DIR/firewall_final.txt"
    fi
    
    # Audit verification
    log "Audit system verification:"
    auditctl -l | tee -a "$EVIDENCE_DIR/audit_final.txt"
    auditctl -s | tee -a "$EVIDENCE_DIR/audit_status_final.txt"
    
    # Service verification
    log "Disabled services verification:"
    for service in cups smb nmb avahi-daemon; do
        systemctl status "$service" 2>/dev/null | grep -E "Active|Loaded" | tee -a "$EVIDENCE_DIR/services_status.txt"
    done
    
    # SSH verification
    log "SSH configuration verification:"
    sshd -T | grep -E 'passwordauthentication|maxauthtries|permitrootlogin|loglevel' | tee -a "$EVIDENCE_DIR/ssh_config.txt"
    
    # Snapshot configs
    log "Creating configuration snapshots..."
    cp /etc/ssh/sshd_config "$EVIDENCE_DIR/sshd_config.snapshot"
    cp /etc/audit/audit.rules "$EVIDENCE_DIR/audit.rules.snapshot" 2>/dev/null
    if command -v ufw &> /dev/null; then
        ufw status verbose > "$EVIDENCE_DIR/ufw.snapshot"
    fi
    
    # Export security policy
    log "Creating security configuration archive..."
    tar -czf "$EVIDENCE_DIR/security-configs.tar.gz" \
        /etc/ssh \
        /etc/audit \
        /etc/systemd/resolved.conf \
        /etc/login.defs \
        /etc/security/pwquality.conf \
        2>/dev/null
    
    # Backup all /etc configurations
    log "Backing up entire /etc directory..."
    cp -r /etc "$BACKUP_DIR/etc-backup-$(date +%F)"
    
    # Create evidence bundle
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
        if command -v firewall-cmd &> /dev/null; then
            firewall-cmd --list-all
        elif command -v ufw &> /dev/null; then
            ufw status verbose
        fi
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
        echo "SUDO USERS"
        echo "========================================="
        grep -E 'sudo|wheel' /etc/group
        echo ""
        echo "========================================="
        echo "RECENT JOURNAL ENTRIES"
        echo "========================================="
        journalctl -b -n 100
    } > "$EVIDENCE_DIR/evidence.txt"
    
    # Display important logs
    log "Recent critical log entries:"
    journalctl -xe -n 50 | tee -a "$EVIDENCE_DIR/recent_logs.txt"
}

################################################################################
# MAIN EXECUTION
################################################################################
main() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     LINUX SYSTEM HARDENING SCRIPT                          ║
║     Blue Team Competition Edition                          ║
║     60-Minute Hardening Timeline                           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log "========================================="
    log "Starting Linux System Hardening"
    log "Operating System: $OS"
    log "========================================="
    
    # Execute hardening functions in order
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
    
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}HARDENING SUCCESSFULLY COMPLETED!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo -e "${YELLOW}Backup Directory:${NC} $BACKUP_DIR"
    echo -e "${YELLOW}Evidence Directory:${NC} $EVIDENCE_DIR"
    echo -e "${YELLOW}Log File:${NC} $LOGFILE"
    echo ""
    echo -e "${RED}CRITICAL REMINDERS:${NC}"
    echo -e "  1. ${YELLOW}Review changes before rebooting!${NC}"
    echo -e "  2. ${YELLOW}Test SSH access in a NEW terminal before closing this session!${NC}"
    echo -e "  3. ${YELLOW}Verify firewall rules allow required services${NC}"
    echo -e "  4. ${YELLOW}Document all changes for competition scoring${NC}"
    echo ""
    
    read -p "Press Enter to view evidence summary..." 
    cat "$EVIDENCE_DIR/evidence.txt"
    echo ""
    
    log "Hardening script completed successfully"
}
