#Requires -RunAsAdministrator
################################################################################
# Windows DNS Server Backup Script
# Purpose: Comprehensive Windows DNS backup for Blue Team Operations
# Usage: Run as Administrator in PowerShell
################################################################################

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Color output functions
function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Failure {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Section {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "$Message" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Configuration
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir = "C:\DNSBackup\backup_$timestamp"
$ArchiveDir = "C:\DNSBackup\Archives"
$LogFile = "C:\DNSBackup\dns_backup.log"
$RetentionDays = 30

# Create directories
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
New-Item -ItemType Directory -Path $ArchiveDir -Force | Out-Null

# Logging function
function Write-Log {
    param([string]$Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Info $Message
}

################################################################################
# DETECT DNS SERVER
################################################################################
function Test-DNSServer {
    Write-Section "Detecting Windows DNS Server"
    
    try {
        $dnsServer = Get-Service -Name DNS -ErrorAction Stop
        
        if ($dnsServer.Status -eq "Running") {
            Write-Success "DNS Server service is running"
            Write-Log "DNS Server detected and running"
            return $true
        } else {
            Write-Warning "DNS Server service is installed but not running: $($dnsServer.Status)"
            $continue = Read-Host "Continue with backup anyway? (y/n)"
            if ($continue -ne 'y') {
                Write-Failure "Backup cancelled by user"
                exit 1
            }
            return $true
        }
    } catch {
        Write-Failure "DNS Server service not found on this system"
        Write-Failure "This script requires Windows DNS Server"
        exit 1
    }
}

################################################################################
# PRE-BACKUP CHECKS
################################################################################
function Test-PreBackupRequirements {
    Write-Section "Pre-Backup Checks"
    
    # Check if DNS PowerShell module is available
    Write-Log "Checking for DNS Server PowerShell module..."
    if (Get-Module -ListAvailable -Name DnsServer) {
        Import-Module DnsServer
        Write-Success "DNS Server PowerShell module loaded"
    } else {
        Write-Warning "DNS Server PowerShell module not available"
        Write-Warning "Some backup operations may be limited"
    }
    
    # Check disk space
    Write-Log "Checking available disk space..."
    $drive = (Get-Item $BackupDir).PSDrive
    $freeSpace = (Get-PSDrive $drive.Name).Free / 1GB
    
    if ($freeSpace -lt 1) {
        Write-Warning "Low disk space: $([math]::Round($freeSpace, 2)) GB available"
    } else {
        Write-Success "Sufficient disk space: $([math]::Round($freeSpace, 2)) GB available"
    }
    
    # Verify dnscmd is available
    Write-Log "Verifying dnscmd availability..."
    try {
        $null = dnscmd /? 2>&1
        Write-Success "dnscmd command is available"
    } catch {
        Write-Warning "dnscmd may not be available"
    }
}

################################################################################
# BACKUP DNS ZONES USING DNSCMD
################################################################################
function Backup-DNSZonesWithDnscmd {
    Write-Section "Backing Up DNS Zones (dnscmd)"
    
    Write-Log "Enumerating DNS zones..."
    
    try {
        # Get list of zones
        $zonesOutput = dnscmd localhost /EnumZones 2>&1
        $zones = $zonesOutput | Where-Object { $_ -notmatch "^Command|^Enumerated|^$" }
        
        $zoneCount = 0
        $zoneDir = "$BackupDir\zones_dnscmd"
        New-Item -ItemType Directory -Path $zoneDir -Force | Out-Null
        
        foreach ($line in $zones) {
            # Parse zone name (first column)
            $zoneName = ($line -split '\s+')[0]
            
            if ($zoneName -and $zoneName -ne "") {
                Write-Log "Backing up zone: $zoneName"
                
                try {
                    # Export zone to file
                    $exportResult = dnscmd localhost /ZoneExport $zoneName "$zoneName.dns" 2>&1
                    
                    if ($LASTEXITCODE -eq 0) {
                        # Copy exported file to backup directory
                        $sourceFile = "$env:SystemRoot\System32\dns\$zoneName.dns"
                        if (Test-Path $sourceFile) {
                            Copy-Item $sourceFile "$zoneDir\$zoneName.dns"
                            Write-Success "Backed up zone: $zoneName"
                            $zoneCount++
                        }
                    } else {
                        Write-Warning "Failed to export zone: $zoneName"
                    }
                } catch {
                    Write-Warning "Error backing up zone ${zoneName}: $_"
                }
            }
        }
        
        Write-Success "Backed up $zoneCount zones using dnscmd"
        Write-Log "Total zones backed up with dnscmd: $zoneCount"
        
    } catch {
        Write-Failure "Error enumerating zones: $_"
    }
}

################################################################################
# BACKUP DNS ZONES USING POWERSHELL
################################################################################
function Backup-DNSZonesWithPowerShell {
    Write-Section "Backing Up DNS Zones (PowerShell)"
    
    try {
        $zones = Get-DnsServerZone -ErrorAction Stop
        $zoneDir = "$BackupDir\zones_powershell"
        New-Item -ItemType Directory -Path $zoneDir -Force | Out-Null
        
        $zoneCount = 0
        
        foreach ($zone in $zones) {
            try {
                Write-Log "Exporting zone: $($zone.ZoneName)"
                Export-DnsServerZone -Name $zone.ZoneName -Path $zoneDir -ErrorAction Stop
                Write-Success "Exported zone: $($zone.ZoneName)"
                $zoneCount++
            } catch {
                Write-Warning "Failed to export zone $($zone.ZoneName): $_"
            }
        }
        
        Write-Success "Backed up $zoneCount zones using PowerShell"
        Write-Log "Total zones backed up with PowerShell: $zoneCount"
        
        # Export zone information
        $zones | Select-Object ZoneName, ZoneType, IsAutoCreated, IsDsIntegrated, IsPaused |
            Export-Csv "$BackupDir\zone_list.csv" -NoTypeInformation
        
        Write-Success "Zone list exported to zone_list.csv"
        
    } catch {
        Write-Warning "PowerShell DNS zone backup not available: $_"
        Write-Warning "Falling back to dnscmd method only"
    }
}

################################################################################
# BACKUP DNS CONFIGURATION
################################################################################
function Backup-DNSConfiguration {
    Write-Section "Backing Up DNS Configuration"
    
    # Backup using dnscmd
    Write-Log "Exporting DNS configuration with dnscmd..."
    $configFile = "$BackupDir\dns_config.txt"
    
    try {
        dnscmd /Config /Export $configFile 2>&1 | Out-Null
        
        if (Test-Path $configFile) {
            Write-Success "DNS configuration exported: dns_config.txt"
        } else {
            Write-Warning "Failed to export DNS configuration"
        }
    } catch {
        Write-Warning "Error exporting DNS configuration: $_"
    }
    
    # Backup DNS registry settings
    Write-Log "Backing up DNS registry settings..."
    $regFile = "$BackupDir\dns_registry.reg"
    
    try {
        reg export HKLM\SYSTEM\CurrentControlSet\Services\DNS $regFile /y | Out-Null
        
        if (Test-Path $regFile) {
            Write-Success "DNS registry settings backed up"
        } else {
            Write-Warning "Failed to backup DNS registry"
        }
    } catch {
        Write-Warning "Error backing up DNS registry: $_"
    }
}

################################################################################
# BACKUP DNS SERVER SETTINGS
################################################################################
function Backup-DNSServerSettings {
    Write-Section "Backing Up DNS Server Settings"
    
    try {
        # Get DNS server configuration
        Write-Log "Capturing DNS server configuration..."
        $dnsServer = Get-DnsServer -ErrorAction Stop
        
        # Export server configuration to JSON
        $dnsServer | ConvertTo-Json -Depth 10 | Out-File "$BackupDir\dns_server_config.json"
        Write-Success "DNS server configuration saved to JSON"
        
        # Get forwarders
        Write-Log "Backing up DNS forwarders..."
        $forwarders = Get-DnsServerForwarder -ErrorAction Stop
        $forwarders | Export-Csv "$BackupDir\dns_forwarders.csv" -NoTypeInformation
        Write-Success "DNS forwarders backed up"
        
        # Get recursion settings
        Write-Log "Backing up recursion settings..."
        $recursion = Get-DnsServerRecursion -ErrorAction Stop
        $recursion | ConvertTo-Json | Out-File "$BackupDir\dns_recursion.json"
        Write-Success "Recursion settings backed up"
        
        # Get scavenging settings
        Write-Log "Backing up scavenging settings..."
        $scavenging = Get-DnsServerScavenging -ErrorAction Stop
        $scavenging | ConvertTo-Json | Out-File "$BackupDir\dns_scavenging.json"
        Write-Success "Scavenging settings backed up"
        
    } catch {
        Write-Warning "Some DNS server settings could not be backed up: $_"
    }
}

################################################################################
# CREATE DNS STATE REPORT
################################################################################
function New-DNSStateReport {
    Write-Section "Creating DNS State Report"
    
    $reportFile = "$BackupDir\dns_state_report.txt"
    
    $report = @"
=========================================
WINDOWS DNS SERVER STATE REPORT
Generated: $(Get-Date)
=========================================

SYSTEM INFORMATION:
Computer Name: $env:COMPUTERNAME
OS Version: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
OS Build: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber)

DNS SERVICE STATUS:
$(Get-Service -Name DNS | Select-Object Name, Status, StartType | Format-List | Out-String)

DNS SERVER CONFIGURATION:
$(try { Get-DnsServer | Select-Object ServerName, ComputerName | Format-List | Out-String } catch { "Not available" })

DNS ZONES:
$(try { Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsAutoCreated, IsDsIntegrated, IsPaused | Format-Table -AutoSize | Out-String } catch { "Not available" })

DNS STATISTICS:
$(try { Get-DnsServerStatistics | Format-List | Out-String } catch { "Not available" })

DNS FORWARDERS:
$(try { Get-DnsServerForwarder | Format-List | Out-String } catch { "Not available" })

DNS RECURSION:
$(try { Get-DnsServerRecursion | Format-List | Out-String } catch { "Not available" })

LISTENING ADDRESSES:
$(Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'} | Select-Object IPAddress, InterfaceAlias | Format-Table -AutoSize | Out-String)

NETWORK CONNECTIONS:
$(Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 53} | Select-Object LocalAddress, LocalPort, State | Format-Table -AutoSize | Out-String)

RECENT EVENT LOG ENTRIES (DNS Server):
$(try { Get-EventLog -LogName "DNS Server" -Newest 20 -ErrorAction SilentlyContinue | Select-Object TimeGenerated, EntryType, Message | Format-Table -AutoSize | Out-String } catch { "Event log not available" })

=========================================
END OF REPORT
=========================================
"@
    
    $report | Out-File $reportFile
    Write-Success "DNS state report created: dns_state_report.txt"
    Write-Log "DNS state report generated"
}

################################################################################
# CREATE COMPRESSED ARCHIVE
################################################################################
function New-BackupArchive {
    Write-Section "Creating Compressed Archive"
    
    $archiveName = "dns_backup_$timestamp.zip"
    $archivePath = "$ArchiveDir\$archiveName"
    
    Write-Log "Creating compressed archive..."
    
    try {
        Compress-Archive -Path "$BackupDir\*" -DestinationPath $archivePath -Force
        
        if (Test-Path $archivePath) {
            $archiveSize = (Get-Item $archivePath).Length / 1MB
            Write-Success "Archive created: $archiveName"
            Write-Success "Archive size: $([math]::Round($archiveSize, 2)) MB"
            Write-Log "Archive created successfully: $archivePath"
            
            # Generate checksum
            $hash = Get-FileHash -Path $archivePath -Algorithm SHA256
            $hash | Export-Csv "$archivePath.checksum.csv" -NoTypeInformation
            
            "$($hash.Algorithm): $($hash.Hash)" | Out-File "$archivePath.checksum.txt"
            
            Write-Success "Checksum generated: SHA256"
            Write-Log "Checksum: $($hash.Hash)"
            
            return $archivePath
        } else {
            Write-Failure "Failed to create archive"
            return $null
        }
    } catch {
        Write-Failure "Error creating archive: $_"
        return $null
    }
}

################################################################################
# VERIFY ARCHIVE INTEGRITY
################################################################################
function Test-BackupArchive {
    param([string]$ArchivePath)
    
    Write-Section "Verifying Archive Integrity"
    
    if (-not (Test-Path $ArchivePath)) {
        Write-Failure "Archive not found: $ArchivePath"
        return $false
    }
    
    Write-Log "Verifying archive integrity..."
    
    try {
        # Test archive by attempting to read contents
        $null = Expand-Archive -Path $ArchivePath -DestinationPath "$env:TEMP\dns_verify_test" -Force
        Remove-Item "$env:TEMP\dns_verify_test" -Recurse -Force
        
        Write-Success "Archive integrity check: PASSED"
        
        # Verify checksum
        if (Test-Path "$ArchivePath.checksum.txt") {
            $storedHash = (Get-Content "$ArchivePath.checksum.txt").Split(':')[1].Trim()
            $currentHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash
            
            if ($storedHash -eq $currentHash) {
                Write-Success "Checksum verification: PASSED"
            } else {
                Write-Failure "Checksum verification: FAILED"
                return $false
            }
        }
        
        return $true
    } catch {
        Write-Failure "Archive integrity check: FAILED - $_"
        return $false
    }
}

################################################################################
# SET SECURE PERMISSIONS
################################################################################
function Set-SecurePermissions {
    param([string]$ArchivePath)
    
    Write-Section "Setting Secure Permissions"
    
    try {
        # Set permissions to Administrators only
        $acl = Get-Acl $ArchivePath
        $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
        
        # Remove all existing access rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        
        # Add Administrators full control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators", "FullControl", "Allow"
        )
        $acl.AddAccessRule($adminRule)
        
        # Add SYSTEM full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "SYSTEM", "FullControl", "Allow"
        )
        $acl.AddAccessRule($systemRule)
        
        Set-Acl -Path $ArchivePath -AclObject $acl
        
        Write-Success "Secure permissions applied (Administrators and SYSTEM only)"
        Write-Log "Secure permissions set on archive"
        
    } catch {
        Write-Warning "Failed to set secure permissions: $_"
    }
}

################################################################################
# COPY TO REMOTE LOCATION (OPTIONAL)
################################################################################
function Copy-BackupRemote {
    param([string]$ArchivePath)
    
    Write-Section "Remote Backup Copy (Optional)"
    
    $copyRemote = Read-Host "Copy backup to remote location? (y/n)"
    
    if ($copyRemote -eq 'y') {
        $remotePath = Read-Host "Enter remote UNC path (e.g., \\server\share\DNS_Backups)"
        
        if ($remotePath) {
            try {
                Write-Log "Copying backup to remote location..."
                Copy-Item -Path $ArchivePath -Destination $remotePath -Force
                Copy-Item -Path "$ArchivePath.checksum.txt" -Destination $remotePath -Force -ErrorAction SilentlyContinue
                
                Write-Success "Backup copied to: $remotePath"
                Write-Log "Backup copied to remote location successfully"
            } catch {
                Write-Failure "Failed to copy to remote location: $_"
            }
        }
    }
}

################################################################################
# CLEANUP OLD BACKUPS
################################################################################
function Remove-OldBackups {
    Write-Section "Cleaning Up Old Backups"
    
    Write-Log "Removing backups older than $RetentionDays days..."
    
    try {
        $oldBackups = Get-ChildItem $ArchiveDir -Filter "dns_backup_*.zip" |
            Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays) }
        
        $deleteCount = 0
        foreach ($backup in $oldBackups) {
            Write-Log "Deleting old backup: $($backup.Name)"
            Remove-Item $backup.FullName -Force
            Remove-Item "$($backup.FullName).checksum.*" -Force -ErrorAction SilentlyContinue
            $deleteCount++
        }
        
        if ($deleteCount -gt 0) {
            Write-Success "Deleted $deleteCount old backup(s)"
        } else {
            Write-Info "No old backups to delete"
        }
        
        # Clean up old backup directories
        Get-ChildItem "C:\DNSBackup" -Directory -Filter "backup_*" |
            Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays) } |
            Remove-Item -Recurse -Force
            
    } catch {
        Write-Warning "Error during cleanup: $_"
    }
}

################################################################################
# GENERATE EVIDENCE REPORT
################################################################################
function New-EvidenceReport {
    param([string]$ArchivePath)
    
    Write-Section "Generating Evidence Report"
    
    $evidenceFile = "$BackupDir\backup_evidence.txt"
    
    $evidence = @"
=========================================
DNS BACKUP EVIDENCE REPORT
Generated: $(Get-Date)
=========================================

BACKUP INFORMATION:
Timestamp: $timestamp
Backup Directory: $BackupDir
Archive Location: $ArchivePath
Archive Size: $([math]::Round((Get-Item $ArchivePath).Length / 1MB, 2)) MB

SYSTEM INFORMATION:
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Domain: $env:USERDOMAIN

DNS SERVICE:
$(Get-Service -Name DNS | Select-Object Name, Status, StartType | Format-List | Out-String)

BACKUP CONTENTS:
$(Get-ChildItem $BackupDir -Recurse | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String)

ARCHIVE CHECKSUM:
$(Get-Content "$ArchivePath.checksum.txt")

DISK SPACE:
$(Get-PSDrive C | Select-Object Name, Used, Free | Format-List | Out-String)

RECENT LOG ENTRIES:
$(Get-Content $LogFile -Tail 30 | Out-String)

=========================================
END OF REPORT
=========================================
"@
    
    $evidence | Out-File $evidenceFile
    Write-Success "Evidence report generated: backup_evidence.txt"
}

################################################################################
# MAIN EXECUTION
################################################################################
function Main {
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "║     WINDOWS DNS SERVER BACKUP SCRIPT                       ║" -ForegroundColor Cyan
    Write-Host "║     Blue Team Operations                                   ║" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log "========================================="
    Write-Log "Starting Windows DNS Backup"
    Write-Log "Timestamp: $timestamp"
    Write-Log "========================================="
    
    try {
        # Execute backup workflow
        Test-DNSServer
        Test-PreBackupRequirements
        Backup-DNSZonesWithDnscmd
        Backup-DNSZonesWithPowerShell
        Backup-DNSConfiguration
        Backup-DNSServerSettings
        New-DNSStateReport
        
        $archivePath = New-BackupArchive
        
        if ($archivePath) {
            Test-BackupArchive -ArchivePath $archivePath
            Set-SecurePermissions -ArchivePath $archivePath
            Copy-BackupRemote -ArchivePath $archivePath
            New-EvidenceReport -ArchivePath $archivePath
            Remove-OldBackups
            
            Write-Section "BACKUP COMPLETE!"
            
            Write-Host "=========================================" -ForegroundColor Green
            Write-Host "WINDOWS DNS BACKUP COMPLETED SUCCESSFULLY!" -ForegroundColor Green
            Write-Host "=========================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "Backup Directory: $BackupDir" -ForegroundColor Yellow
            Write-Host "Archive Location: $archivePath" -ForegroundColor Yellow
            Write-Host "Log File: $LogFile" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Next Steps:" -ForegroundColor Cyan
            Write-Host "  1. Verify backup integrity" -ForegroundColor White
            Write-Host "  2. Test restoration in lab environment" -ForegroundColor White
            Write-Host "  3. Store backup in secure off-site location" -ForegroundColor White
            Write-Host "  4. Update backup documentation" -ForegroundColor White
            Write-Host "  5. Review evidence report: $BackupDir\backup_evidence.txt" -ForegroundColor White
            Write-Host ""
            
            $viewReport = Read-Host "View evidence report? (y/n)"
            if ($viewReport -eq 'y') {
                Get-Content "$BackupDir\backup_evidence.txt"
            }
        } else {
            Write-Failure "Backup failed - archive was not created"
        }
        
    } catch {
        Write-Failure "An error occurred during backup: $_"
        Write-Log "ERROR: $_"
    }
    
    Write-Log "Windows DNS backup script completed"
}

# Trap for cleanup
trap {
    Write-Log "Script interrupted"
    exit 1
}

# Run the main function
Main
