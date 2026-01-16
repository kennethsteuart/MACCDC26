Write-Host "[+] Hunting malicious processes..."

$suspiciousPatterns = @(
    "powershell.*-enc",
    "cmd.exe /c",
    "nc.exe",
    "ncat.exe",
    "certutil",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "bitsadmin"
)

Get-CimInstance Win32_Process | ForEach-Object {
    foreach ($pattern in $suspiciousPatterns) {
        if ($_.CommandLine -match $pattern) {
            Write-Host "[!] Killing $($_.Name) PID $($_.ProcessId)"
            Stop-Process -Id $_.ProcessId -Force
        }
    }
}

Write-Host "[+] Done."
