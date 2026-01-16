# MACCDC Windows Server 2019 AD/DNS Hardening Script
# Run as Administrator
# Test in lab before competition!

#Requires -RunAsAdministrator

# Color output functions
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

# Create log file
$LogFile = "C:\Hardening_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $LogFile

Write-Info "=== MACCDC Server Hardening Script ==="
Write-Info "Started at: $(Get-Date)"
Write-Warn "This script will make significant security changes to your system"
Write-Warn "Press Ctrl+C to cancel, or any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# =====================================
# 1. AUDIT LOGGING
# =====================================
Write-Info "`n[1/10] Configuring Audit Policies..."
try {
    auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
    Write-Success "Audit policies configured"
} catch {
    Write-Fail "Failed to configure audit policies: $_"
}

# =====================================
# 2. DISABLE DANGEROUS SERVICES
# =====================================
Write-Info "`n[2/10] Disabling unnecessary services..."
$ServicesToDisable = @(
    "Spooler",           # Print Spooler
    "RemoteRegistry",    # Remote Registry
    "WMPNetworkSvc",     # Windows Media Player Network Sharing
    "XblAuthManager",    # Xbox Live Auth Manager
    "XblGameSave",       # Xbox Live Game Save
    "XboxGipSvc",        # Xbox Accessory Management
    "XboxNetApiSvc"      # Xbox Live Networking
)

foreach ($svc in $ServicesToDisable) {
    try {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled
            Write-Success "Disabled service: $svc"
        }
    } catch {
        Write-Warn "Could not disable $svc (may not exist): $_"
    }
}

# =====================================
# 3. DISABLE SMBv1
# =====================================
Write-Info "`n[3/10] Disabling SMBv1..."
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Write-Success "SMBv1 disabled (reboot required)"
    } else {
        Write-Success "SMBv1 already disabled"
    }
} catch {
    Write-Fail "Failed to disable SMBv1: $_"
}

# =====================================
# 4. ENABLE SMB SIGNING & ENCRYPTION
# =====================================
Write-Info "`n[4/10] Configuring SMB security..."
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -EncryptData $true -Confirm:$false
    Write-Success "SMB signing and encryption enabled"
} catch {
    Write-Fail "Failed to configure SMB security: $_"
}

# =====================================
# 5. WINDOWS FIREWALL
# =====================================
Write-Info "`n[5/10] Configuring Windows Firewall..."
try {
    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Success "Firewall enabled for all profiles"
    
    # Set default actions
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Success "Default firewall policy: Block inbound, Allow outbound"
    
    # Essential AD/DNS rules
    $firewallRules = @(
        @{Name="DNS-UDP-In"; Protocol="UDP"; Port=53; Description="DNS Server UDP"},
        @{Name="DNS-TCP-In"; Protocol="TCP"; Port=53; Description="DNS Server TCP"},
        @{Name="Kerberos-TCP-In"; Protocol="TCP"; Port=88; Description="Kerberos Authentication TCP"},
        @{Name="Kerberos-UDP-In"; Protocol="UDP"; Port=88; Description="Kerberos Authentication UDP"},
        @{Name="LDAP-TCP-In"; Protocol="TCP"; Port=389; Description="LDAP TCP"},
        @{Name="LDAP-UDP-In"; Protocol="UDP"; Port=389; Description="LDAP UDP"},
        @{Name="LDAPS-In"; Protocol="TCP"; Port=636; Description="LDAP over SSL"},
        @{Name="GC-LDAP-In"; Protocol="TCP"; Port=3268; Description="Global Catalog LDAP"},
        @{Name="GC-LDAPS-In"; Protocol="TCP"; Port=3269; Description="Global Catalog LDAP SSL"},
        @{Name="SMB-In"; Protocol="TCP"; Port=445; Description="SMB over TCP"},
        @{Name="RDP-In"; Protocol="TCP"; Port=3389; Description="Remote Desktop"}
    )
    
    foreach ($rule in $firewallRules) {
        if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol $rule.Protocol -LocalPort $rule.Port -Action Allow -Description $rule.Description | Out-Null
            Write-Success "Created firewall rule: $($rule.Name)"
        }
    }
} catch {
    Write-Fail "Failed to configure firewall: $_"
}

# =====================================
# 6. DNS SECURITY
# =====================================
Write-Info "`n[6/10] Hardening DNS configuration..."
try {
    # Enable DNS socket pool
    dnscmd . /config /socketpoolsize 2500 | Out-Null
    Write-Success "DNS socket pool enabled (size: 2500)"
    
    # Enable DNS cache locking
    dnscmd . /config /cachelockingpercent 100 | Out-Null
    Write-Success "DNS cache locking enabled at 100%"
    
    Write-Warn "Remember to manually configure DNS zone transfer restrictions and scavenging in DNS Manager"
} catch {
    Write-Fail "Failed to configure DNS security: $_"
}

# =====================================
# 7. REGISTRY HARDENING
# =====================================
Write-Info "`n[7/10] Applying registry hardening..."
try {
    # Disable LM hash storage
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord
    Write-Success "Disabled LM hash storage"
    
    # Set LAN Manager authentication level (NTLMv2 only)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord
    Write-Success "Set authentication to NTLMv2 only"
    
    # Disable anonymous SID enumeration
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord
    Write-Success "Restricted anonymous access"
    
    # Disable LLMNR
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Success "LLMNR disabled"
    
    # Disable NetBIOS over TCP/IP (requires network adapter loop)
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null
    }
    Write-Success "NetBIOS over TCP/IP disabled"
    
} catch {
    Write-Fail "Failed to apply registry hardening: $_"
}

# =====================================
# 8. ACCOUNT SECURITY
# =====================================
Write-Info "`n[8/10] Configuring account security..."
try {
    # Disable Guest account
    try {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        Write-Success "Guest account disabled"
    } catch {
        # Try AD version if local doesn't work
        Disable-ADAccount -Identity "Guest" -ErrorAction SilentlyContinue
        Write-Success "AD Guest account disabled"
    }
    
    # Rename Administrator account (optional - be careful!)
    Write-Warn "Administrator account rename skipped - do manually if needed"
    
} catch {
    Write-Fail "Failed to configure account security: $_"
}

# =====================================
# 9. PASSWORD POLICY (via Local Security Policy)
# =====================================
Write-Info "`n[9/10] Configuring password policies..."
try {
    $secpolCfg = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditAccountLogon = 3
[Version]
signature="$CHICAGO$"
Revision=1
"@
    
    $secpolFile = "$env:TEMP\secpol.cfg"
    $secpolCfg | Out-File -FilePath $secpolFile -Encoding ASCII
    secedit /configure /db secedit.sdb /cfg $secpolFile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $secpolFile -Force
    Write-Success "Password and account lockout policies configured"
} catch {
    Write-Fail "Failed to configure password policies: $_"
}

# =====================================
# 10. CREATE MONITORING TASKS
# =====================================
Write-Info "`n[10/10] Creating monitoring scheduled tasks..."
try {
    # Create a simple monitoring script
    $monitorScript = @'
$events = @()
$events += Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 -ErrorAction SilentlyContinue | Select TimeGenerated, Message
$events += Get-EventLog -LogName Security -InstanceId 4672 -Newest 10 -ErrorAction SilentlyContinue | Select TimeGenerated, Message

if ($events.Count -gt 0) {
    $events | Out-File "C:\SecurityMonitor.log" -Append
}
'@
    
    $monitorScript | Out-File "C:\MonitorSecurity.ps1" -Force
    
    # Create scheduled task to run every 15 minutes
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\MonitorSecurity.ps1"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 365)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    Register-ScheduledTask -TaskName "SecurityMonitoring" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Success "Security monitoring task created (runs every 15 minutes)"
} catch {
    Write-Fail "Failed to create monitoring tasks: $_"
}

# =====================================
# SUMMARY AND RECOMMENDATIONS
# =====================================
Write-Info "`n=== HARDENING COMPLETE ==="
Write-Info "Log file saved to: $LogFile"
Write-Success "`nCompleted automated hardening steps!"

Write-Warn "`nMANUAL STEPS STILL REQUIRED:"
Write-Host "  1. Change ALL passwords (Administrator, Domain Admin, service accounts, krbtgt)" -ForegroundColor Yellow
Write-Host "  2. Review Domain Admins group membership" -ForegroundColor Yellow
Write-Host "  3. Configure DNS zone transfer restrictions in DNS Manager" -ForegroundColor Yellow
Write-Host "  4. Enable DNS scavenging in DNS Manager" -ForegroundColor Yellow
Write-Host "  5. Review and remove unnecessary user accounts" -ForegroundColor Yellow
Write-Host "  6. Test all scoring services to ensure they still work!" -ForegroundColor Yellow
Write-Host "  7. Configure Group Policy Objects for domain-wide settings" -ForegroundColor Yellow
Write-Host "  8. Review scheduled tasks: Get-ScheduledTask" -ForegroundColor Yellow
Write-Host "  9. Check for backdoor accounts: Get-ADUser -Filter *" -ForegroundColor Yellow
Write-Host "  10. Backup critical configurations" -ForegroundColor Yellow

Write-Warn "`nREBOOT REQUIRED for some changes to take effect (especially SMBv1 disable)"
Write-Info "`nWould you like to reboot now? (y/n)"
$reboot = Read-Host

if ($reboot -eq 'y') {
    Write-Info "Rebooting in 60 seconds... Press Ctrl+C to cancel"
    shutdown /r /t 60
} else {
    Write-Info "Remember to reboot when safe to do so!"
}

Stop-Transcript
