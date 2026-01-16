```powershell
# Incident Response Playbook - Windows
# Run as Administrator
# Replace ATTACKER_IP, ADMIN_IP, SESSION_ID, PID_NUMBER as needed

$ADMIN_IP = "ADMIN_IP"
$SESSION_ID = "SESSION_ID"
$PID_NUMBER = "PID_NUMBER"

Write-Host "[+] Starting Windows Incident Response Actions"

#######################################
# Phase 2: Containment
#######################################

Write-Host "[+] Isolating host (block all except RDP from admin)"
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

netsh advfirewall firewall add rule `
  name="Allow Admin RDP In" `
  dir=in action=allow protocol=TCP localport=3389 remoteip=$ADMIN_IP

netsh advfirewall firewall add rule `
  name="Allow Admin RDP Out" `
  dir=out action=allow protocol=TCP localport=3389 remoteip=$ADMIN_IP

#######################################
# Kill Active Sessions
#######################################

Write-Host "[+] Active user sessions:"
query user

if ($SESSION_ID -ne "SESSION_ID") {
  Write-Host "[+] Logging off session $SESSION_ID"
  logoff $SESSION_ID
}

if ($PID_NUMBER -ne "PID_NUMBER") {
  Write-Host "[+] Killing PID $PID_NUMBER"
  taskkill /F /PID $PID_NUMBER
}

#######################################
# Phase 3: Eradication Checks
#######################################

Write-Host "[+] Checking scheduled tasks"
schtasks /query /fo LIST /v
schtasks /query /fo CSV > C:\IR_scheduled_tasks.csv

Write-Host "[+] Checking running services"
Get-Service | Where-Object {$_.Status -eq "Running"}

Get-WmiObject win32_service |
  Select-Object Name, PathName, StartMode |
  Format-List

Write-Host "[+] Checking startup registry keys"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

Write-Host "[+] Checking startup folders"
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

Write-Host "[+] Checking local users"
net user
net localgroup Administrators
Get-WmiObject Win32_UserAccount | Select Name, Disabled, LocalAccount

Write-Host "[+] Checking network connections"
netstat -ano | findstr ESTABLISHED
netstat -ano | findstr LISTENING

#######################################
# Phase 4: Recovery
#######################################

Write-Host "[+] To restore firewall when safe:"
Write-Host "    netsh advfirewall reset"

Write-Host "[+] Windows incident response script completed"
```
