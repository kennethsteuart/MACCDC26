# DNS Server Backup Guide for Blue Team Operations

A comprehensive guide for backing up DNS servers during blue team defensive operations.

## Table of Contents

- [Windows DNS Server](#windows-dns-server)
- [BIND DNS Server (Linux)](#bind-dns-server-linux)
- [General Best Practices](#general-best-practices)
- [Blue Team Considerations](#blue-team-considerations)

---

## Windows DNS Server

### Using dnscmd (Built-in)

```bash
# Backup all zones
dnscmd /ZoneExport <zonename> <filename>

# Example for a specific zone
dnscmd localhost /ZoneExport contoso.com contoso.com.dns

# Backup DNS server configuration
dnscmd /Config /Export c:\backup\dns_config.txt
```

### Using PowerShell

```powershell
# Export all DNS zones
Get-DnsServerZone | Export-DnsServerZone -Path "C:\DNSBackup"

# Backup specific zone
Export-DnsServerZone -Name "contoso.com" -FileName "contoso.com.bak"

# Full DNS server backup
Backup-DnsServerZone -Name "." -Path "C:\DNSBackup"
```

### Registry Backup (DNS Settings)

```bash
reg export HKLM\SYSTEM\CurrentControlSet\Services\DNS C:\backup\dns_registry.reg
```

---

## BIND DNS Server (Linux)

### Configuration and Zone Files

```bash
# Backup BIND configuration
cp /etc/bind/named.conf /backup/named.conf.bak
cp -r /etc/bind/zones /backup/zones_backup/

# Or tar the entire directory
tar -czf dns_backup_$(date +%Y%m%d).tar.gz /etc/bind /var/cache/bind

# Backup zone files specifically
cp /var/cache/bind/*.zone /backup/zones/
```

### Using rndc

```bash
# Sync zones to disk before backup
rndc sync -clean

# Freeze a zone (stop updates during backup)
rndc freeze example.com
# ... perform backup ...
rndc thaw example.com
```

---

## General Best Practices

### Create Timestamped Backups

```bash
# Create timestamped backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
tar -czf dns_backup_$TIMESTAMP.tar.gz /path/to/dns/files

# Verify backup integrity
tar -tzf dns_backup_$TIMESTAMP.tar.gz

# Copy to secure location
scp dns_backup_$TIMESTAMP.tar.gz backup-server:/secure/location/

# Document the backup
echo "Backup completed: $TIMESTAMP" >> /var/log/dns_backup.log
```

### Automated Backup Script Example (Linux)

```bash
#!/bin/bash
# DNS Backup Script

BACKUP_DIR="/backup/dns"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="dns_backup_$TIMESTAMP.tar.gz"

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Sync zones to disk
rndc sync -clean

# Create compressed backup
tar -czf $BACKUP_DIR/$BACKUP_FILE /etc/bind /var/cache/bind

# Verify backup
if [ -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
    echo "Backup successful: $BACKUP_FILE" >> /var/log/dns_backup.log
else
    echo "Backup failed: $BACKUP_FILE" >> /var/log/dns_backup.log
    exit 1
fi

# Remove backups older than 30 days
find $BACKUP_DIR -name "dns_backup_*.tar.gz" -mtime +30 -delete
```

### Automated Backup Script Example (Windows PowerShell)

```powershell
# DNS Backup Script for Windows
$BackupDir = "C:\DNSBackup"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFile = "dns_backup_$Timestamp"

# Create backup directory if it doesn't exist
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir
}

# Export all DNS zones
Get-DnsServerZone | ForEach-Object {
    Export-DnsServerZone -Name $_.ZoneName -Path "$BackupDir\$BackupFile"
}

# Backup DNS registry settings
reg export HKLM\SYSTEM\CurrentControlSet\Services\DNS "$BackupDir\$BackupFile\dns_registry.reg"

# Log the backup
Add-Content -Path "$BackupDir\backup_log.txt" -Value "Backup completed: $Timestamp"

# Remove backups older than 30 days
Get-ChildItem $BackupDir -Directory | Where-Object {$_.CreationTime -lt (Get-Date).AddDays(-30)} | Remove-Item -Recurse
```

---

## Blue Team Considerations

### Pre-Backup Checklist

- **Document current state**: Capture running config, zone serial numbers, and record counts
- **Verify DNS service status**: Ensure DNS is running normally before backup
- **Check disk space**: Ensure sufficient space for backup files
- **Review recent changes**: Document any recent DNS modifications

### Backup Strategy

- **Frequency**: Daily automated backups at minimum, more frequent for critical infrastructure
- **Retention**: Keep at least 30 days of backups, longer for compliance requirements
- **Storage locations**: 
  - Primary: Local secure storage
  - Secondary: Off-site or cloud backup
  - Tertiary: Offline/cold storage for disaster recovery

### Security Measures

```bash
# Encrypt backup files
gpg --encrypt --recipient admin@company.com dns_backup.tar.gz

# Set proper permissions (Linux)
chmod 600 dns_backup_*.tar.gz
chown root:root dns_backup_*.tar.gz

# Windows: Restrict access using ACLs
icacls C:\DNSBackup /inheritance:r /grant:r "Administrators:(OI)(CI)F"
```

### Testing and Validation

```bash
# Test backup restoration in lab environment
# 1. Extract backup
tar -xzf dns_backup_20240115_120000.tar.gz -C /test/restore/

# 2. Verify file integrity
md5sum /test/restore/etc/bind/* > checksum.txt

# 3. Test zone file syntax
named-checkzone example.com /test/restore/etc/bind/zones/example.com.zone

# 4. Test configuration syntax
named-checkconf /test/restore/etc/bind/named.conf
```

### Monitoring and Alerting

- Set up alerts for backup failures
- Monitor backup file sizes for anomalies
- Verify backup completion in logs
- Test restoration procedures quarterly

### Incident Response Integration

- Include DNS backups in incident response playbooks
- Document restoration procedures
- Maintain offline copies for ransomware scenarios
- Version control for configuration changes

### Compliance and Documentation

- Maintain backup logs for audit trails
- Document backup and restoration procedures
- Track backup success/failure rates
- Regular review and update of backup policies

---

## Quick Reference Commands

### Windows

```bash
# Quick zone export
dnscmd /ZoneExport <zonename> <filename>

# PowerShell full backup
Get-DnsServerZone | Export-DnsServerZone -Path "C:\DNSBackup"
```

### Linux

```bash
# Quick BIND backup
tar -czf dns_backup.tar.gz /etc/bind /var/cache/bind

# Sync and freeze
rndc sync -clean && rndc freeze
```

---

## Additional Resources

- [Microsoft DNS Server Documentation](https://docs.microsoft.com/en-us/windows-server/networking/dns/)
- [BIND 9 Administrator Reference Manual](https://bind9.readthedocs.io/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## License

This guide is provided for educational and defensive security purposes only.

## Contributing

Feel free to submit issues and enhancement requests for this guide.
