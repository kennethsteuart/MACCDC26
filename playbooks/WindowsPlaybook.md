# Windows Incident Response & Hardening Playbook

## Minute 0: Pre-Flight & Roles

* Identify RDP-capable defenders ("Remote Desktop" group)
* Enforce least privilege for all defender accounts
* Firewall rule: allow inbound RDP **only** from jump box / white team
* Split defenders into parallel tracks:

  * **PowerShell Track**: rapid containment via local scripts
  * **GPO Track**: domain-wide enforcement (slower but persistent)
* Ensure network profile is **not Public**

```powershell
Get-NetConnectionProfile
Set-NetConnectionProfile -NetworkCategory Private
# or
Set-NetConnectionProfile -NetworkCategory DomainAuthenticated
```

---

## Minutes 1–10: Firewall Default Deny & Logging

### Configure Firewall Logging

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "$LogPath\Firewall.log"
Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
```

### Allow Required Inbound Traffic

```powershell
# RDP from Jump Box only
New-NetFirewallRule -DisplayName "SECURE_RDP_JumpboxOnly" `
  -Direction Inbound `
  -LocalPort 3389 `
  -Protocol TCP `
  -RemoteAddress $JumpBoxIP `
  -Action Allow

# Scoring Engine
New-NetFirewallRule -DisplayName "SECURE_ScoringEngine" `
  -Direction Inbound `
  -RemoteAddress $ScoringIP `
  -Action Allow

# ICMP (Ping)
New-NetFirewallRule -DisplayName "SECURE_ICMP_Ping" `
  -Direction Inbound `
  -Protocol ICMPv4 `
  -Action Allow
```

### Enforce Default Deny

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
```

---

## Minutes 11–20: Accounts, Passwords, Lockouts

### Password Policy

```cmd
net accounts /minpwlen:14 /uniquepw:24
net accounts /maxpwage:90 /minpwage:1
```

### Account Lockout

```cmd
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
```

### Disable & Rename Accounts

```cmd
net user guest /active:no
```

* Rename default Administrator/Guest accounts to non-obvious names

### Verification (Evidence)

```cmd
net user guest
net user administrator
net accounts
```

---

## Minutes 21–30: Kill Pivot Services

### Disable Print Spooler

```powershell
Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
Set-Service -Name Spooler -StartupType Disabled
```

### Disable SMBv1

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
```

### Disable Discovery / Legacy Services

```powershell
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
  Set-Service -Name $Svc -StartupType Disabled
}
```

### Disable Remote Assistance

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
```

### Disable Autorun / Autoplay

```powershell
$AutoRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (!(Test-Path $AutoRunPath)) { New-Item -Path $AutoRunPath -Force | Out-Null }
New-ItemProperty -Path $AutoRunPath -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force | Out-Null

$AutoPlayPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
if (!(Test-Path $AutoPlayPath)) { New-Item -Path $AutoPlayPath -Force | Out-Null }
New-ItemProperty -Path $AutoPlayPath -Name "DisableAutoplay" -Value 1 -PropertyType DWORD -Force | Out-Null
```

---

## Minutes 31–40: Credential & Protocol Hardening

### Enable LSA Protection (Reboot Required)

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f
```

### Force NTLMv2 Only (GPO)

* **Security Options → Network Security → LAN Manager Authentication Level**
* Set to: **Send NTLMv2 response only. Refuse LM & NTLM**

### Disable LLMNR

```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
```

### Harden NetBIOS (P-node)

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters /v NodeType /t REG_DWORD /d 2 /f
```

### Verification

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel
reg query "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast
reg query HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters /v NodeType
```

---

## Minutes 41–50: Advanced Auditing

### Force Subcategory Auditing

```powershell
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (!(Test-Path $LsaPath)) { New-Item -Path $LsaPath -Force | Out-Null }
New-ItemProperty -Path $LsaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -PropertyType DWORD -Force | Out-Null
```

### Enable Command Line Logging

```powershell
$AuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (!(Test-Path $AuditPath)) { New-Item -Path $AuditPath -Force | Out-Null }
New-ItemProperty -Path $AuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWORD -Force | Out-Null
```

### Granular Audit Policy

```cmd
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable

auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable

auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:disable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:disable

auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
```

* Key Events:

  * **4688** – Process Creation
  * **4625** – Failed Logon

---

## Minutes 51–55: Allow-Lists Only

```powershell
New-NetFirewallRule -DisplayName "Allow RDP from Jump" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress <jumpbox_IP> -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

* **No Any/Any rules**

### Verification

```powershell
Get-NetFirewallRule | Where-Object {$_.Direction -eq "Inbound"} | Format-Table Name, Enabled, LocalPort, RemoteAddress
```

---

## Minutes 56–60: Verification, Snapshots, Evidence

```powershell
$LogPath = "C:\HardeningLogs"
if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Force -Path $LogPath | Out-Null }

auditpol /get /category:* | Out-File "$LogPath\AuditPolicy_Final.txt"
auditpol /get /category:"Detailed Tracking","Logon/Logoff","Object Access"
```

### Firewall Verification

```powershell
$FW = Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction, LogMaxSizeKilobytes
foreach ($Profile in $FW) {
  if ($Profile.Enabled -and $Profile.DefaultInboundAction -eq "Block" -and $Profile.LogMaxSizeKilobytes -ge 16384) {
    Write-Host "[PASS] $($Profile.Name)" -ForegroundColor Green
  } else {
    Write-Host "[FAIL] $($Profile.Name)" -ForegroundColor Red
  }
}
```

### Service Verification

```powershell
$Spooler = Get-Service Spooler -ErrorAction SilentlyContinue
```

### Export Security Baseline

```cmd
secedit /export /cfg C:\HardeningLogs\Final_Security_Baseline.inf
```
