# =====================================
# MACCDC DNS Recovery Script
# Restores DNS to functional state after hardening
# Run as Administrator
# =====================================

# --- Helper Functions for Output ---
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

# --- 1. Ensure hosts file has proper entries ---
try {
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $dcFQDN = (Get-ADDomain).DNSRoot
    $dcName = $env:COMPUTERNAME
    $hostsContent = @"
127.0.0.1       localhost
::1             localhost
$((Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" | Select-Object -First 1).IPAddress)   $dcFQDN $dcName
"@
    $hostsContent | Set-Content -Path $hostsPath -Force
    Write-Success "Hosts file updated"
} catch {
    Write-Fail "Failed to update hosts file: $_"
}

# --- 2. Temporarily disable firewall to allow internal DNS ---
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
    Write-Warn "Firewall temporarily disabled"
} catch {
    Write-Fail "Failed to disable firewall: $_"
}

# --- 3. Restart necessary services ---
$services = @("DNS", "ADWS", "NTDS")
foreach ($svc in $services) {
    try {
        Restart-Service -Name $svc -Force -ErrorAction Stop
        Write-Success "$svc restarted"
    } catch {
        Write-Fail "Failed to restart $svc: $_"
    }
}

# --- 4. Flush DNS cache and re-register ---
try {
    ipconfig /flushdns
    ipconfig /registerdns
    Write-Success "DNS cache flushed and re-registered"
} catch {
    Write-Fail "Failed to flush/re-register DNS: $_"
}

# --- 5. Verify DNS is listening on port 53 ---
$tcp53 = Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue
$udp53 = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue

if ($tcp53 -or $udp53) {
    Write-Success "DNS server is listening on port 53"
} else {
    Write-Fail "DNS server is NOT listening on port 53"
}

# --- 6. Test DNS resolution locally ---
try {
    $ns1 = nslookup localhost 2>&1
    $ns2 = nslookup 127.0.0.1 2>&1
    if ($ns1 -match "Name:" -and $ns2 -match "Name:") {
        Write-Success "Local DNS resolution working (localhost & 127.0.0.1)"
    } else {
        Write-Fail "Local DNS resolution FAILED"
    }
} catch {
    Write-Fail "Error testing local DNS: $_"
}

# --- 7. Optional: Re-enable firewall (comment out if you want firewall disabled) ---
#Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
#Write-Success "Firewall re-enabled"

# --- 8. Final message ---
Write-Host ""
Write-Host "=== DNS Recovery Script Complete ===" -ForegroundColor Cyan
Write-Host "Check nslookup localhost and dcdiag /test:DNS to verify full functionality." -ForegroundColor Cyan
