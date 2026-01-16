#!/bin/bash
################################################################################
# BIND DNS Server Backup Script for Linux
# Purpose: Comprehensive BIND DNS backup for Blue Team Operations
# Usage: sudo ./dns_backup_linux.sh
################################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/dns_${TIMESTAMP}"
ARCHIVE_DIR="/backup"
LOG_FILE="/var/log/dns_backup.log"
RETENTION_DAYS=30

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

section() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}\n"
}

################################################################################
# DETECT BIND INSTALLATION
################################################################################
detect_bind() {
    section "Detecting BIND DNS Server"
    
    # Check if BIND is installed
    if command -v named &> /dev/null; then
        log "BIND DNS server detected: $(named -v)"
    elif [ -f /etc/bind/named.conf ] || [ -f /etc/named.conf ]; then
        log "BIND configuration found"
    else
        error "BIND DNS server not found on this system"
        error "This script is for BIND DNS servers only"
        exit 1
    fi
    
    # Detect configuration directory
    if [ -f /etc/bind/named.conf ]; then
        BIND_CONF_DIR="/etc/bind"
        BIND_ZONE_DIR="/var/cache/bind"
        BIND_SERVICE="bind9"
    elif [ -f /etc/named.conf ]; then
        BIND_CONF_DIR="/etc"
        BIND_ZONE_DIR="/var/named"
        BIND_SERVICE="named"
    else
        error "Could not determine BIND configuration directory"
        exit 1
    fi
    
    log "Configuration directory: $BIND_CONF_DIR"
    log "Zone directory: $BIND_ZONE_DIR"
    log "Service name: $BIND_SERVICE"
}

################################################################################
# PRE-BACKUP CHECKS
################################################################################
pre_backup_checks() {
    section "Pre-Backup Checks"
    
    # Check BIND service status
    log "Checking BIND service status..."
    if systemctl is-active --quiet "$BIND_SERVICE"; then
        log "BIND service is running"
    else
        warn "BIND service is not running"
        read -p "Continue with backup anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Backup cancelled by user"
            exit 1
        fi
    fi
    
    # Check disk space
    log "Checking available disk space..."
    AVAILABLE_SPACE=$(df /backup 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    REQUIRED_SPACE=1048576  # 1GB in KB
    
    if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
        warn "Low disk space: $(df -h /backup | awk 'NR==2 {print $4}') available"
    else
        log "Sufficient disk space available: $(df -h /backup | awk 'NR==2 {print $4}')"
    fi
    
    # Create backup directories
    log "Creating backup directory structure..."
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$ARCHIVE_DIR"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        error "Failed to create backup directory: $BACKUP_DIR"
        exit 1
    fi
}

################################################################################
# SYNC ZONES TO DISK
################################################################################
sync_zones() {
    section "Syncing Zones to Disk"
    
    if command -v rndc &> /dev/null; then
        log "Syncing all zones to disk..."
        rndc sync -clean 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log "Zones synced successfully"
        else
            warn "rndc sync failed - continuing anyway"
        fi
        
        # Get rndc status
        log "Current BIND status:"
        rndc status | tee -a "$BACKUP_DIR/rndc_status.txt"
    else
        warn "rndc not available - skipping zone sync"
    fi
}

################################################################################
# BACKUP CONFIGURATION FILES
################################################################################
backup_configuration() {
    section "Backing Up Configuration Files"
    
    log "Backing up BIND configuration..."
    
    # Backup main configuration directory
    if [ -d "$BIND_CONF_DIR" ]; then
        cp -r "$BIND_CONF_DIR" "$BACKUP_DIR/bind_config"
        log "Configuration directory backed up"
        
        # List configuration files
        find "$BACKUP_DIR/bind_config" -type f > "$BACKUP_DIR/config_file_list.txt"
        log "Configuration file list created"
    else
        error "Configuration directory not found: $BIND_CONF_DIR"
    fi
    
    # Backup additional BIND-related configs
    if [ -f /etc/resolv.conf ]; then
        cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.bak"
        log "Backed up /etc/resolv.conf"
    fi
    
    if [ -f /etc/hosts ]; then
        cp /etc/hosts "$BACKUP_DIR/hosts.bak"
        log "Backed up /etc/hosts"
    fi
}

################################################################################
# BACKUP ZONE FILES
################################################################################
backup_zones() {
    section "Backing Up Zone Files"
    
    log "Backing up zone files..."
    
    # Create zones directory in backup
    mkdir -p "$BACKUP_DIR/zones"
    
    # Backup all zone files
    if [ -d "$BIND_ZONE_DIR" ]; then
        # Copy .zone files
        find "$BIND_ZONE_DIR" -name "*.zone" -exec cp {} "$BACKUP_DIR/zones/" \; 2>/dev/null
        
        # Copy entire zone directory structure
        cp -r "$BIND_ZONE_DIR" "$BACKUP_DIR/bind_zones"
        
        # Count zone files
        ZONE_COUNT=$(find "$BACKUP_DIR/zones" -name "*.zone" | wc -l)
        log "Backed up $ZONE_COUNT zone files"
        
        # List all zone files
        ls -lh "$BACKUP_DIR/zones" > "$BACKUP_DIR/zone_file_list.txt"
    else
        warn "Zone directory not found: $BIND_ZONE_DIR"
    fi
    
    # Extract zone names from configuration
    log "Extracting zone information from configuration..."
    if [ -f "$BIND_CONF_DIR/named.conf" ]; then
        grep -E "zone.*{" "$BIND_CONF_DIR/named.conf" > "$BACKUP_DIR/zone_names.txt"
    elif [ -f /etc/named.conf ]; then
        grep -E "zone.*{" /etc/named.conf > "$BACKUP_DIR/zone_names.txt"
    fi
}

################################################################################
# VALIDATE ZONE FILES
################################################################################
validate_zones() {
    section "Validating Zone Files"
    
    log "Validating zone file syntax..."
    
    VALIDATION_REPORT="$BACKUP_DIR/zone_validation_report.txt"
    echo "Zone Validation Report - $(date)" > "$VALIDATION_REPORT"
    echo "======================================" >> "$VALIDATION_REPORT"
    echo "" >> "$VALIDATION_REPORT"
    
    VALID_COUNT=0
    INVALID_COUNT=0
    
    # Validate each zone file
    for zone_file in "$BACKUP_DIR/zones"/*.zone; do
        if [ -f "$zone_file" ]; then
            zone_name=$(basename "$zone_file" .zone)
            
            if command -v named-checkzone &> /dev/null; then
                if named-checkzone "$zone_name" "$zone_file" >> "$VALIDATION_REPORT" 2>&1; then
                    echo "[OK] $zone_name" >> "$VALIDATION_REPORT"
                    ((VALID_COUNT++))
                else
                    echo "[FAIL] $zone_name" >> "$VALIDATION_REPORT"
                    ((INVALID_COUNT++))
                fi
            fi
        fi
    done
    
    echo "" >> "$VALIDATION_REPORT"
    echo "Summary: $VALID_COUNT valid, $INVALID_COUNT invalid" >> "$VALIDATION_REPORT"
    
    log "Zone validation complete: $VALID_COUNT valid, $INVALID_COUNT invalid"
    
    # Validate main configuration
    if command -v named-checkconf &> /dev/null; then
        log "Validating BIND configuration syntax..."
        if [ -f "$BACKUP_DIR/bind_config/named.conf" ]; then
            if named-checkconf "$BACKUP_DIR/bind_config/named.conf" 2>&1 | tee -a "$VALIDATION_REPORT"; then
                log "Configuration syntax is valid"
            else
                warn "Configuration syntax validation failed"
            fi
        fi
    fi
}

################################################################################
# CREATE STATE REPORT
################################################################################
create_state_report() {
    section "Creating DNS State Report"
    
    REPORT_FILE="$BACKUP_DIR/dns_state_report.txt"
    
    {
        echo "========================================="
        echo "BIND DNS STATE REPORT"
        echo "Generated: $(date)"
        echo "========================================="
        echo ""
        echo "SYSTEM INFORMATION:"
        echo "Hostname: $(hostname)"
        echo "OS: $(uname -s) $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo ""
        echo "BIND VERSION:"
        named -v 2>/dev/null || echo "Unable to determine version"
        echo ""
        echo "SERVICE STATUS:"
        systemctl status "$BIND_SERVICE" --no-pager 2>/dev/null || echo "Status not available"
        echo ""
        echo "RNDC STATUS:"
        rndc status 2>/dev/null || echo "rndc not available"
        echo ""
        echo "CONFIGURATION DIRECTORY:"
        echo "$BIND_CONF_DIR"
        ls -lh "$BIND_CONF_DIR" 2>/dev/null
        echo ""
        echo "ZONE DIRECTORY:"
        echo "$BIND_ZONE_DIR"
        ls -lh "$BIND_ZONE_DIR" 2>/dev/null
        echo ""
        echo "ZONE LIST:"
        if [ -f "$BIND_CONF_DIR/named.conf" ]; then
            grep -E "zone.*{" "$BIND_CONF_DIR/named.conf" 2>/dev/null
        elif [ -f /etc/named.conf ]; then
            grep -E "zone.*{" /etc/named.conf 2>/dev/null
        fi
        echo ""
        echo "LISTENING INTERFACES:"
        netstat -tulnp | grep named 2>/dev/null || ss -tulnp | grep named 2>/dev/null || echo "Not available"
        echo ""
        echo "RECENT LOG ENTRIES:"
        journalctl -u "$BIND_SERVICE" -n 50 --no-pager 2>/dev/null || tail -50 /var/log/syslog 2>/dev/null | grep named
        echo ""
        echo "========================================="
    } > "$REPORT_FILE"
    
    log "DNS state report created: $REPORT_FILE"
}

################################################################################
# CREATE COMPRESSED ARCHIVE
################################################################################
create_archive() {
    section "Creating Compressed Archive"
    
    ARCHIVE_NAME="dns_backup_${TIMESTAMP}.tar.gz"
    ARCHIVE_PATH="$ARCHIVE_DIR/$ARCHIVE_NAME"
    
    log "Creating compressed archive..."
    tar -czf "$ARCHIVE_PATH" -C "$BACKUP_DIR" . 2>/dev/null
    
    if [ $? -eq 0 ]; then
        log "Archive created: $ARCHIVE_PATH"
        
        # Get archive size
        ARCHIVE_SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)
        log "Archive size: $ARCHIVE_SIZE"
        
        # Set secure permissions
        chmod 600 "$ARCHIVE_PATH"
        chown root:root "$ARCHIVE_PATH"
        log "Secure permissions set (600, root:root)"
        
    else
        error "Failed to create archive"
        return 1
    fi
}

################################################################################
# VERIFY ARCHIVE INTEGRITY
################################################################################
verify_archive() {
    section "Verifying Archive Integrity"
    
    ARCHIVE_NAME="dns_backup_${TIMESTAMP}.tar.gz"
    ARCHIVE_PATH="$ARCHIVE_DIR/$ARCHIVE_NAME"
    
    if [ -f "$ARCHIVE_PATH" ]; then
        log "Verifying archive integrity..."
        
        if tar -tzf "$ARCHIVE_PATH" > /dev/null 2>&1; then
            log "Archive integrity check: PASSED"
            
            # Generate checksum
            MD5SUM=$(md5sum "$ARCHIVE_PATH" | cut -d' ' -f1)
            SHA256SUM=$(sha256sum "$ARCHIVE_PATH" | cut -d' ' -f1)
            
            echo "MD5: $MD5SUM" > "${ARCHIVE_PATH}.checksum"
            echo "SHA256: $SHA256SUM" >> "${ARCHIVE_PATH}.checksum"
            
            log "Checksums generated:"
            log "  MD5: $MD5SUM"
            log "  SHA256: $SHA256SUM"
            
            # Display archive contents (first 20 files)
            log "Archive contents (first 20 files):"
            tar -tzf "$ARCHIVE_PATH" | head -20 | tee -a "$LOG_FILE"
            
            return 0
        else
            error "Archive integrity check: FAILED"
            return 1
        fi
    else
        error "Archive not found: $ARCHIVE_PATH"
        return 1
    fi
}

################################################################################
# ENCRYPT BACKUP (OPTIONAL)
################################################################################
encrypt_backup() {
    section "Backup Encryption (Optional)"
    
    read -p "Encrypt backup with GPG? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if ! command -v gpg &> /dev/null; then
            error "GPG not found - install gpg to use encryption"
            return 1
        fi
        
        read -p "Enter recipient email for GPG encryption: " recipient
        
        ARCHIVE_NAME="dns_backup_${TIMESTAMP}.tar.gz"
        ARCHIVE_PATH="$ARCHIVE_DIR/$ARCHIVE_NAME"
        
        if [ -f "$ARCHIVE_PATH" ]; then
            log "Encrypting backup with GPG..."
            gpg --encrypt --recipient "$recipient" "$ARCHIVE_PATH"
            
            if [ $? -eq 0 ]; then
                log "Backup encrypted: ${ARCHIVE_PATH}.gpg"
                
                # Generate checksum for encrypted file
                SHA256SUM=$(sha256sum "${ARCHIVE_PATH}.gpg" | cut -d' ' -f1)
                echo "Encrypted SHA256: $SHA256SUM" > "${ARCHIVE_PATH}.gpg.checksum"
                
                read -p "Remove unencrypted backup? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    rm "$ARCHIVE_PATH"
                    rm "${ARCHIVE_PATH}.checksum"
                    log "Unencrypted backup removed"
                fi
            else
                error "GPG encryption failed"
                return 1
            fi
        fi
    fi
}

################################################################################
# COPY TO REMOTE SERVER (OPTIONAL)
################################################################################
remote_backup() {
    section "Remote Backup Copy (Optional)"
    
    read -p "Copy backup to remote server? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter remote destination (user@host:/path): " remote_dest
        
        ARCHIVE_NAME="dns_backup_${TIMESTAMP}.tar.gz"
        
        # Determine which file to copy
        if [ -f "$ARCHIVE_DIR/${ARCHIVE_NAME}.gpg" ]; then
            COPY_FILE="$ARCHIVE_DIR/${ARCHIVE_NAME}.gpg"
            CHECKSUM_FILE="${COPY_FILE}.checksum"
        elif [ -f "$ARCHIVE_DIR/${ARCHIVE_NAME}" ]; then
            COPY_FILE="$ARCHIVE_DIR/${ARCHIVE_NAME}"
            CHECKSUM_FILE="${COPY_FILE}.checksum"
        else
            error "No backup file found to copy"
            return 1
        fi
        
        log "Copying backup to remote server..."
        scp "$COPY_FILE" "$remote_dest"
        
        if [ $? -eq 0 ]; then
            log "Backup copied successfully"
            
            # Copy checksum file too
            if [ -f "$CHECKSUM_FILE" ]; then
                scp "$CHECKSUM_FILE" "$remote_dest"
                log "Checksum file copied"
            fi
        else
            error "Failed to copy backup to remote server"
            return 1
        fi
    fi
}

################################################################################
# CLEANUP OLD BACKUPS
################################################################################
cleanup_old_backups() {
    section "Cleaning Up Old Backups"
    
    log "Removing backups older than $RETENTION_DAYS days..."
    
    # Find and delete old archives
    DELETED_COUNT=0
    
    while IFS= read -r old_file; do
        log "Deleting old backup: $(basename "$old_file")"
        rm "$old_file"
        ((DELETED_COUNT++))
    done < <(find "$ARCHIVE_DIR" -name "dns_backup_*.tar.gz*" -mtime +$RETENTION_DAYS)
    
    if [ "$DELETED_COUNT" -gt 0 ]; then
        log "Deleted $DELETED_COUNT old backup file(s)"
    else
        log "No old backups to delete"
    fi
    
    # Clean up old backup directories
    find /backup -maxdepth 1 -type d -name "dns_*" -mtime +$RETENTION_DAYS -exec rm -rf {} \; 2>/dev/null
}

################################################################################
# GENERATE EVIDENCE REPORT
################################################################################
generate_evidence() {
    section "Generating Evidence Report"
    
    EVIDENCE_FILE="$BACKUP_DIR/backup_evidence.txt"
    
    {
        echo "========================================="
        echo "DNS BACKUP EVIDENCE REPORT"
        echo "Generated: $(date)"
        echo "========================================="
        echo ""
        echo "BACKUP INFORMATION:"
        echo "Timestamp: $TIMESTAMP"
        echo "Backup Directory: $BACKUP_DIR"
        echo "Archive Directory: $ARCHIVE_DIR"
        echo ""
        echo "SYSTEM INFORMATION:"
        echo "Hostname: $(hostname)"
        echo "OS: $(uname -s) $(uname -r)"
        echo ""
        echo "BIND INFORMATION:"
        echo "Service: $BIND_SERVICE"
        echo "Configuration: $BIND_CONF_DIR"
        echo "Zones: $BIND_ZONE_DIR"
        echo ""
        echo "BACKUP CONTENTS:"
        ls -lhR "$BACKUP_DIR"
        echo ""
        echo "ARCHIVE INFORMATION:"
        ls -lh "$ARCHIVE_DIR"/dns_backup_${TIMESTAMP}*
        echo ""
        if [ -f "$ARCHIVE_DIR/dns_backup_${TIMESTAMP}.tar.gz.checksum" ]; then
            echo "CHECKSUMS:"
            cat "$ARCHIVE_DIR/dns_backup_${TIMESTAMP}.tar.gz.checksum"
            echo ""
        fi
        echo "DISK USAGE:"
        df -h /backup
        echo ""
        echo "RECENT LOG ENTRIES:"
        tail -30 "$LOG_FILE"
        echo ""
        echo "========================================="
        echo "END OF REPORT"
        echo "========================================="
    } > "$EVIDENCE_FILE"
    
    log "Evidence report generated: $EVIDENCE_FILE"
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
║     BIND DNS BACKUP SCRIPT - LINUX                         ║
║     Blue Team Operations                                   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log "========================================="
    log "Starting BIND DNS Backup"
    log "Timestamp: $TIMESTAMP"
    log "========================================="
    
    # Execute backup workflow
    detect_bind
    pre_backup_checks
    sync_zones
    backup_configuration
    backup_zones
    validate_zones
    create_state_report
    create_archive
    verify_archive
    encrypt_backup
    remote_backup
    cleanup_old_backups
    generate_evidence
    
    section "BACKUP COMPLETE!"
    
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}BIND DNS BACKUP COMPLETED SUCCESSFULLY!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo ""
    echo -e "${YELLOW}Backup Directory:${NC} $BACKUP_DIR"
    echo -e "${YELLOW}Archive Location:${NC} $ARCHIVE_DIR/dns_backup_${TIMESTAMP}.tar.gz"
    echo -e "${YELLOW}Log File:${NC} $LOG_FILE"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  1. Verify backup integrity: tar -tzf $ARCHIVE_DIR/dns_backup_${TIMESTAMP}.tar.gz"
    echo "  2. Test restoration in lab environment"
    echo "  3. Store backup in secure off-site location"
    echo "  4. Update backup documentation"
    echo "  5. Review evidence report: $BACKUP_DIR/backup_evidence.txt"
    echo ""
    
    log "BIND DNS backup script completed successfully"
}

# Trap for cleanup on exit
trap 'log "Script interrupted"; exit 1' INT TERM

# Run main function
main
