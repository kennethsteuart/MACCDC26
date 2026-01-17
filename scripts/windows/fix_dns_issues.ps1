# =========================================
# MACCDC Lab DNS Recovery Script
# Reverts changes that could break internal DNS
# Run as Administrator
# =========================================

Write-Host "=== MACCDC Lab DNS Recovery Script ===" -ForegroundColor Cyan

# -----------------------------
# 1. Revert firewall changes affecting DNS / RPC
# -----------------------------
Write-Host "[*] Restoring firewall rules for DNS and RPC..." -ForegroundColor Cyan

# Allow DNS TCP/UDP 53
New-NetFirewallRule -DisplayName "Allow DNS TCP 53" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Domain -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow DNS UDP 53" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Domain -ErrorAction SilentlyContinue

# Allow RPC Endpoint Mapper
New-NetFirewallRule -DisplayName "Allow RPC TCP 135" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Allow -Profile Domain -ErrorAction SilentlyContinue

# Allow Dynamic RPC Ports 49152-65535
New-NetFirewallRule -DisplayName "Allow RPC Dynamic TCP" -Direction Inbound -Protocol TCP -LocalPort 49152-65535 -Action Allow -Profile Domain -ErrorAction SilentlyContinue

Write-Host "[+] Firewall rules restored" -ForegroundColor Green

# -----------------------------
# 2. Revert DNS cache locking and socket pool
# -----------------------------
Write-Host "[*] Reverting DNS cache locking and socket pool..." -ForegroundColor Cyan

# Reset cache locking to default
dnscmd . /config /cachelockingpercent 50
# Reset socket pool to default
dnscmd . /config /socketpoolsize 0
# Clear DNS cache
dnscmd /clearcache

Write-Host "[+] DNS cache and socket pool reset" -ForegroundColor Green

# -----------------------------
# 3. Re-enable dynamic updates for zones
# -----------------------------
Write-Host "[*] Checking DNS zones for dynamic updates..." -ForegroundColor Cyan
try {
    Import-Module DNSServer -ErrorAction Stop
    $zones = Get-DnsServerZone | Where-Object { $_.ZoneType -eq "Primary" -and $_.IsDsIntegrated -eq $true }
    foreach ($zone in $zones) {
        Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate Secure
        Write-Host "[+] Dynamic updates enabled for zone: $($zone.ZoneName)" -ForegroundColor Green
    }
} catch {
    Write-Warn "[!] Could not modify zones. Ensure DNSServer module is installed."
}

# -----------------------------
# 4. Force DC to register its own DNS records
# -----------------------------
Write-Host "[*] Forcing DC to register DNS records..." -ForegroundColor Cyan
ipconfig /registerdns
Write-Host "[+] DNS registration triggered" -ForegroundColor Green

# -----------------------------
# 5. Re-enable NetBIOS over TCP/IP (lab safe)
# -----------------------------
Write-Host "[*] Re-enabling NetBIOS over TCP/IP..." -ForegroundColor Cyan
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(1) | Out-Null  # 1 = Enable
}
Write-Host "[+] NetBIOS over TCP/IP re-enabled" -ForegroundColor Green

# -----------------------------
# 6. Revert anonymous restrictions (lab safe)
# -----------------------------
Write-Host "[*] Reverting LSA anonymous restrictions..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 0 -Type DWord
Write-Host "[+] LSA anonymous restrictions reverted (requires reboot for full effect)" -ForegroundColor Green

# -----------------------------
# 7. Reminder to reboot
# -----------------------------
Write-Host "`n=== DNS Recovery Script Completed ===" -ForegroundColor Cyan
Write-Host "Please reboot the server to apply all changes, especially LSA/NetBIOS/firewall adjustments." -ForegroundColor Yellow
Write-Host "After reboot, run: dcdiag /test:DNS /v" -ForegroundColor Yellow
