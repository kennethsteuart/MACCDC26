#Requires -RunAsAdministrator
################################################################################
# Windows System Hardening Script for Blue Team Competition
# Purpose: CCDC/Red Team vs Blue Team rapid system hardening
# Usage: Run as Administrator in PowerShell
# Based on 60-minute hardening timeline
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

# Create log and evidence directories
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogPath = "C:\HardeningLogs_$timestamp"
$BackupPath = "C:\HardeningBackup_$timestamp"
$EvidencePath = "C:\Evidence_$timestamp"

New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null

$logFile = "$LogPath\hardening_log.txt"

# Logging function
function Write-Log {
    param([string]$Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Info $Message
}

################################################################################
# MINUTE 0: PRE-FLIGHT & ROLES
################################################################################
function PreFlight-Setup {
    Write-Section "MINUTE 0: Pre-Flight & Roles"
    
    Write-Log "Starting pre-flight checks..."
    
    # Export current user and group information
    Get-LocalUser | Export-Csv "$BackupPath\local_users.csv" -NoTypeInformation
    Get-LocalGroup | Export-Csv "$BackupPath\local_groups.csv" -NoTypeInformation
    
    # Check and set network profile
    Write-Log "Checking network profile..."
    $profile = Get-NetConnectionProfile
    $profile | Export-Csv "$EvidencePath\network_profile_before.csv" -NoTypeInformation
    
    if ($profile.NetworkCategory -eq "Public") {
        Write-Warning "Network profile is Public - changing to Private"
        Set-NetConnectionProfile -NetworkCategory Private
        Write-Success "Network profile set to Private"
    } else {
        Write-Success "Network profile is: $($profile.NetworkCategory)"
    }
    
    # Backup registry keys
    Write-Log "Backing up critical registry keys..."
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$BackupPath\lsa_backup.reg" /y | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" "$BackupPath\policies_backup.reg" /y | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "$BackupPath\netbt_backup.reg" /y | Out-Null
    
    Write-Success "Pre-flight setup completed"
}

################################################################################
# MINUTES 1-10: FIREWALL TO DEFAULT DENY AND LOGGING
################################################################################
function Configure-Firewall {
    Write-Section "MINUTES 1-10: Firewall to Default Deny and Logging"
    
    # Get Jump Box IP and Scoring IP from user
    $JumpBoxIP = Read-Host "Enter Jump Box IP address (e.g., 10.0.5.10)"
    $ScoringIP = Read-Host "Enter Scoring Engine IP address (or press Enter to skip)"
    
    # Configure firewall logging
    Write-Log "Configuring firewall logging..."
    $FirewallLogPath = "$LogPath\Firewall.log"
    
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName $FirewallLogPath
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
    
    Write-Success "Firewall logging configured (16MB, all events)"
    
    # Allow RDP from Jump Box only
    Write-Log "Creating RDP allow rule for Jump Box only..."
    New-NetFirewallRule -DisplayName "SECURE_RDP_JumpboxOnly" `
        -Direction Inbound `
        -LocalPort 3389 `
        -Protocol TCP `
        -RemoteAddress $JumpBoxIP `
        -Action Allow `
        -ErrorAction SilentlyContinue
    
    Write-Success "RDP allowed from Jump Box: $JumpBoxIP"
    
    # Allow scoring engine if provided
    if ($ScoringIP) {
        Write-Log "Creating allow rule for Scoring Engine..."
        New-NetFirewallRule -DisplayName "SECURE_ScoringEngine" `
            -Direction Inbound `
            -RemoteAddress $ScoringIP `
            -Action Allow `
            -ErrorAction SilentlyContinue
        
        Write-Success "Scoring Engine allowed from: $ScoringIP"
    }
    
    # Allow ICMP ping
    Write-Log "Allowing ICMP ping..."
    New-NetFirewallRule -DisplayName "SECURE_ICMP_Ping" `
        -Direction Inbound `
        -Protocol ICMPv4 `
        -Action Allow `
        -ErrorAction SilentlyContinue
    
    Write-Success "ICMP ping allowed"
    
    # Apply baseline block for all inbound traffic
    Write-Log "Applying DEFAULT DENY for inbound traffic..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    
    Write-Success "Firewall set to DEFAULT DENY (block all inbound)"
    
    # Export firewall configuration
    Get-NetFirewallProfile | Export-Csv "$EvidencePath\firewall_profiles.csv" -NoTypeInformation
    Get-NetFirewallRule | Where-Object {$_.Direction -eq "Inbound"} | 
        Export-Csv "$EvidencePath\inbound_rules.csv" -NoTypeInformation
}

################################################################################
# MINUTES 11-20: ACCOUNTS, PASSWORDS, LOCKOUTS
################################################################################
function Harden-Accounts {
    Write-Section "MINUTES 11-20: Accounts, Passwords, and Lockouts"
    
    # Enforce strong passwords - minimum length 14, password history 24
    Write-Log "Enforcing strong password policies..."
    net accounts /minpwlen:14 /uniquepw:24
    
    # Password aging - max 90 days, min 1 day
    Write-Log "Setting password aging policies..."
    net accounts /maxpwage:90 /minpwage:1
    
    Write-Success "Password policies set (14 chars, 24 history, 90 max age)"
    
    # Account lockout threshold
    Write-Log "Setting account lockout policies..."
    net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
    
    Write-Success "Lockout policy set (5 attempts, 30 min duration)"
    
    # Disable guest account
    Write-Log "Disabling guest account..."
    net user guest /active:no
    
    Write-Success "Guest account disabled"
    
    # Prompt to rename administrator account
    Write-Warning "MANUAL STEP: Consider renaming Administrator account to non-obvious name"
    Write-Warning "Use: wmic useraccount where name='Administrator' rename <NewName>"
    
    # Export account evidence
    Write-Log "Exporting account evidence..."
    net user guest | Out-File "$EvidencePath\guest_account.txt"
    net user administrator | Out-File "$EvidencePath\admin_account.txt"
    net accounts | Out-File "$EvidencePath\account_policies.txt"
    
    Write-Success "Account evidence exported"
}

################################################################################
# MINUTES 21-30: KILL THE PIVOTS
################################################################################
function Kill-Pivots {
    Write-Section "MINUTES 21-30: Kill the Pivots (Spooler, SMBv1, AutoRun)"
    
    # Kill Print Spooler
    Write-Log "Stopping and disabling Print Spooler..."
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Success "Print Spooler disabled"
    
    # Kill SMBv1
    Write-Log "Disabling SMBv1 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Write-Success "SMBv1 disabled"
    
    # Disable Helper/Discovery Services
    Write-Log "Disabling dangerous services..."
    $BadServices = @(
        "RemoteRegistry",
        "SSDPSRV",
        "upnphost",
        "lmhosts",
        "TlntSvr",
        "SimpTcp"
    )
    
    foreach ($Svc in $BadServices) {
        Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $Svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Success "Disabled service: $Svc"
    }
    
    # Disable Remote Assistance
    Write-Log "Disabling Remote Assistance..."
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
        -Name 'fAllowToGetHelp' -Value 0 -ErrorAction SilentlyContinue
    Write-Success "Remote Assistance disabled"
    
    # Disable AutoRun on all drives
    Write-Log "Disabling AutoRun/AutoPlay..."
    $AutoRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (!(Test-Path $AutoRunPath)) {
        New-Item -Path $AutoRunPath -Force | Out-Null
    }
    New-ItemProperty -Path $AutoRunPath -Name "NoDriveTypeAutoRun" `
        -Value 255 -PropertyType DWORD -Force | Out-Null
    
    # Disable AutoPlay in Explorer
    $AutoPlayPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    if (!(Test-Path $AutoPlayPath)) {
        New-Item -Path $AutoPlayPath -Force | Out-Null
    }
    New-ItemProperty -Path $AutoPlayPath -Name "DisableAutoplay" `
        -Value 1 -PropertyType DWORD -Force | Out-Null
    
    Write-Success "AutoRun/AutoPlay disabled on all drives"
}

################################################################################
# MINUTES 31-40: CREDENTIAL & PROTOCOL HARDENING
################################################################################
function Harden-Credentials {
    Write-Section "MINUTES 31-40: Credential & Protocol Hardening"
    
    # Enable LSA Protection (RunAsPPL)
    Write-Log "Enabling LSA Protection (RunAsPPL)..."
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
    Write-Success "LSA Protection enabled (requires reboot)"
    
    # Force NTLMv2, refuse LM/NTLM
    Write-Log "Forcing NTLMv2 only authentication..."
    reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
    Write-Success "NTLMv2-only authentication enforced"
    
    # Disable LLMNR
    Write-Log "Disabling LLMNR..."
    reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f | Out-Null
    Write-Success "LLMNR disabled"
    
    # Configure NetBIOS node type (P-node)
    Write-Log "Configuring NetBIOS to P-node..."
    reg add HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters /v NodeType /t REG_DWORD /d 2 /f | Out-Null
    Write-Success "NetBIOS set to P-node (no broadcast)"
    
    # Verify all changes
    Write-Log "Verifying credential hardening..."
    reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL | Out-File "$EvidencePath\lsa_runas_ppl.txt"
    reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel | Out-File "$EvidencePath\lm_compat.txt"
    reg query "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast | Out-File "$EvidencePath\llmnr_status.txt"
    reg query HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters /v NodeType | Out-File "$EvidencePath\netbios_node.txt"
    
    Write-Success "Credential hardening evidence exported"
}

################################################################################
# MINUTES 41-50: ADVANCED AUDITING
################################################################################
function Configure-AdvancedAuditing {
    Write-Section "MINUTES 41-50: Advanced Auditing"
    
    # Force Subcategories
    Write-Log "Forcing subcategory audit policy..."
    $LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    if (!(Test-Path $LsaPath)) {
        New-Item -Path $LsaPath -Force | Out-Null
    }
    New-ItemProperty -Path $LsaPath -Name "SCENoApplyLegacyAuditPolicy" `
        -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Success "Subcategory Audit Policy enforced"
    
    # Command Line Argument Logging
    Write-Log "Enabling command line argument logging..."
    $AuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (!(Test-Path $AuditPath)) {
        New-Item -Path $AuditPath -Force | Out-Null
    }
    New-ItemProperty -Path $AuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" `
        -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Success "Command Line Argument Logging enabled"
    
    # Apply granular audit policies
    Write-Log "Applying granular audit policies..."
    
    # Account Logon
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    
    # Logon/Logoff
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
    auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
    
    # Detailed Tracking (Process Creation)
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
    
    # Object Access (File Shares and Removable Drives)
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"Detailed File Share" /success:disable /failure:enable
    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    
    # Policy Change (Firewall and Audit Policy)
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:disable
    
    # Privilege Use
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
    
    # System
    auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
    
    Write-Success "Granular audit policies applied"
    
    # Export audit policy
    auditpol /get /category:* | Out-File "$EvidencePath\audit_policy.txt"
    
    Write-Warning "Check Event Viewer (Security) for Event ID 4688 (Process) & 4625 (Failed Logons)"
}

################################################################################
# MINUTES 51-55: ALLOW-LISTS ONLY
################################################################################
function Configure-AllowLists {
    Write-Section "MINUTES 51-55: Allow-Lists Only"
    
    Write-Warning "Current firewall should be DEFAULT DENY"
    Write-Log "Configuring allow-list rules for required services..."
    
    # Prompt for required services
    $needDNS = Read-Host "Is this a DNS server? (y/n)"
    $needHTTP = Read-Host "Is this a web server (HTTP/HTTPS)? (y/n)"
    $customPorts = Read-Host "Any custom ports to allow? (comma-separated, or Enter to skip)"
    
    if ($needDNS -eq 'y') {
        Write-Log "Adding DNS allow rule..."
        New-NetFirewallRule -DisplayName "Allow DNS" `
            -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
        Write-Success "DNS (UDP/53) allowed"
    }
    
    if ($needHTTP -eq 'y') {
        Write-Log "Adding HTTP/HTTPS allow rules..."
        New-NetFirewallRule -DisplayName "Allow HTTP" `
            -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
        New-NetFirewallRule -DisplayName "Allow HTTPS" `
            -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
        Write-Success "HTTP (80) and HTTPS (443) allowed"
    }
    
    if ($customPorts) {
        $ports = $customPorts -split ','
        foreach ($port in $ports) {
            $port = $port.Trim()
            Write-Log "Adding custom port $port..."
            New-NetFirewallRule -DisplayName "Custom Port $port" `
                -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow
            Write-Success "Custom port $port allowed"
        }
    }
    
    # Verify NO any/any rules exist
    Write-Warning "Verifying no 'any/any' rules exist..."
    $anyRules = Get-NetFirewallRule | Where-Object {
        $_.Direction -eq "Inbound" -and 
        $_.RemoteAddress -eq "Any" -and 
        $_.Action -eq "Allow"
    }
    
    if ($anyRules) {
        Write-Failure "WARNING: Found potentially dangerous 'any/any' allow rules:"
        $anyRules | Select-Object DisplayName, RemoteAddress, Action | Format-Table
    } else {
        Write-Success "No dangerous 'any/any' rules found"
    }
    
    # Export final firewall rules
    Get-NetFirewallRule | Where-Object {$_.Direction -eq "Inbound"} | 
        Select-Object DisplayName, Enabled, Direction, Action, LocalPort, RemoteAddress |
        Export-Csv "$EvidencePath\final_inbound_rules.csv" -NoTypeInformation
}

################################################################################
# MINUTES 56-60: VERIFY, SNAPSHOT, EVIDENCE
################################################################################
function Verify-Hardening {
    Write-Section "MINUTES 56-60: Verify, Snapshot, Evidence"
    
    Write-Log "Running final verification checks..."
    
    # Verify Audit Policy
    Write-Log "Verifying audit policy..."
    $AuditStatus = auditpol /get /category:*
    $AuditStatus | Out-File "$EvidencePath\AuditPolicy_Final.txt"
    auditpol /get /category:"Detailed Tracking","Logon/Logoff","Object Access" | 
        Out-File "$EvidencePath\AuditPolicy_Critical.txt"
    Write-Success "Audit policy verified and exported"
    
    # Verify Firewall State
    Write-Log "Verifying firewall state..."
    $FW = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, LogMaxSizeKilobytes
    
    foreach ($Profile in $FW) {
        if ($Profile.Enabled -eq $True -and 
            $Profile.DefaultInboundAction -eq "Block" -and 
            $Profile.LogMaxSizeKilobytes -ge 16384) {
            Write-Success "[PASS] $($Profile.Name): ON | BLOCK | LOGGING ($($Profile.LogMaxSizeKilobytes)KB)"
        } else {
            Write-Failure "[FAIL] $($Profile.Name): Enabled=$($Profile.Enabled) | Inbound=$($Profile.DefaultInboundAction) | LogSize=$($Profile.LogMaxSizeKilobytes)"
        }
    }
    
    $FW | Export-Csv "$EvidencePath\Firewall_Final_Status.csv" -NoTypeInformation
    
    # Verify killed services
    Write-Log "Verifying disabled services..."
    
    # Check Print Spooler
    $Spooler = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($Spooler.Status -eq "Stopped" -and $Spooler.StartType -eq "Disabled") {
        Write-Success "[PASS] Spooler is STOPPED and DISABLED"
    } else {
        Write-Failure "[FAIL] Spooler is $($Spooler.Status) / $($Spooler.StartType)"
    }
    
    # Check SMBv1
    try {
        $SMBv1 = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
        if ($SMBv1.EnableSMB1Protocol -eq $False) {
            Write-Success "[PASS] SMBv1 is DISABLED"
        } else {
            Write-Failure "[FAIL] SMBv1 is ENABLED"
        }
    } catch {
        Write-Info "[INFO] SMBv1 check skipped (already removed or command unavailable)"
    }
    
    # Export service status
    Get-Service | Where-Object {
        $_.Name -in @("Spooler", "RemoteRegistry", "SSDPSRV", "upnphost", "lmhosts", "TlntSvr", "SimpTcp")
    } | Select-Object Name, Status, StartType | 
        Export-Csv "$EvidencePath\Disabled_Services_Status.csv" -NoTypeInformation
    
    # Export Security Config
    Write-Log "Exporting security baseline configuration..."
    cmd.exe /c "secedit /export /cfg $EvidencePath\Final_Security_Baseline.inf"
    
    if (Test-Path "$EvidencePath\Final_Security_Baseline.inf") {
        Write-Success "[PASS] Secedit config saved"
    } else {
        Write-Failure "[FAIL] Secedit export failed"
    }
    
    # Create comprehensive evidence report
    Write-Log "Creating comprehensive evidence report..."
    
    $report = @"
========================================
WINDOWS SYSTEM HARDENING EVIDENCE REPORT
Generated: $(Get-Date)
========================================

SYSTEM INFORMATION:
$(systeminfo | Select-String "OS Name","OS Version","System Type")

FIREWALL STATUS:
$($FW | Format-Table -AutoSize | Out-String)

ACCOUNT POLICIES:
$(net accounts)

DISABLED SERVICES:
Spooler: $($Spooler.Status) / $($Spooler.StartType)

REGISTRY HARDENING:
LSA Protection (RunAsPPL): $(reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL 2>$null)
LM Compatibility Level: $(reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel 2>$null)
LLMNR Disabled: $(reg query "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast 2>$null)
NetBIOS Node Type: $(reg query HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters /v NodeType 2>$null)

INBOUND FIREWALL RULES:
$(Get-NetFirewallRule | Where-Object {$_.Direction -eq "Inbound" -and $_.Enabled -eq $true} | Select-Object DisplayName, LocalPort, RemoteAddress | Format-Table -AutoSize | Out-String)

========================================
END OF REPORT
========================================
"@
    
    $report | Out-File "$EvidencePath\Comprehensive_Evidence_Report.txt"
    Write-Success "Comprehensive evidence report created"
}

################################################################################
# MAIN EXECUTION
################################################################################
function Main {
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "║     WINDOWS SYSTEM HARDENING SCRIPT                        ║" -ForegroundColor Cyan
    Write-Host "║     Blue Team Competition Edition                          ║" -ForegroundColor Cyan
    Write-Host "║     60-Minute Hardening Timeline                           ║" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log "========================================="
    Write-Log "Starting Windows System Hardening"
    Write-Log "========================================="
    
    try {
        # Execute hardening functions in order
        PreFlight-Setup
        Configure-Firewall
        Harden-Accounts
        Kill-Pivots
        Harden-Credentials
        Configure-AdvancedAuditing
        Configure-AllowLists
        Verify-Hardening
        
        Write-Section "HARDENING COMPLETE!"
        
        Write-Host "=========================================" -ForegroundColor Green
        Write-Host "HARDENING SUCCESSFULLY COMPLETED!" -ForegroundColor Green
        Write-Host "=========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Log Directory: $LogPath" -ForegroundColor Yellow
        Write-Host "Backup Directory: $BackupPath" -ForegroundColor Yellow
        Write-Host "Evidence Directory: $EvidencePath" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "CRITICAL REMINDERS:" -ForegroundColor Red
        Write-Host "  1. " -NoNewline
        Write-Host "LSA Protection requires a REBOOT to take effect" -ForegroundColor Yellow
        Write-Host "  2. " -NoNewline
        Write-Host "Test RDP access from jump box before closing this session" -ForegroundColor Yellow
        Write-Host "  3. " -NoNewline
        Write-Host "Review Event Viewer > Security for Event IDs 4688 & 4625" -ForegroundColor Yellow
        Write-Host "  4. " -NoNewline
        Write-Host "Document all changes for competition scoring" -ForegroundColor Yellow
        Write-Host ""
        
        $viewReport = Read-Host "View comprehensive evidence report? (y/n)"
        if ($viewReport -eq 'y') {
            Get-Content "$EvidencePath\Comprehensive_Evidence_Report.txt"
        }
        
        Write-Host ""
        $reboot = Read-Host "Reboot now to apply LSA Protection? (y/n)"
        if ($reboot -eq 'y') {
            Write-Warning "Rebooting in 30 seconds... Press Ctrl+C to cancel"
            Start-Sleep -Seconds 30
            Restart-Computer -Force
        }
        
    } catch {
        Write-Failure "An error occurred: $_"
        Write-Log "ERROR: $_"
    }
    
    Write-Log "Hardening script completed"
}

# Trap for cleanup
trap {
    Write-Log "Script interrupted"
    exit 1
}

# Run the main function
Main
