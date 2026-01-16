<#
Splunk Universal Forwarder installer/config with list/dry-run/apply/backup/restore.
Run in elevated PowerShell for apply/backup/restore.
#>
param(
  [ValidateSet("list", "dry-run", "apply", "backup", "restore")]
  [string]$Mode = "list",
  [string]$InstallerPath = "",
  [string]$Indexer = "172.20.242.20",
  [int]$Port = 9997,
  [string]$SplunkHome = "C:\Program Files\SplunkUniversalForwarder",
  [string]$SplunkPass = "",
  [string]$BackupDir = "",
  [string]$RestoreFrom = ""
)

function Write-Log { param([string]$Message) $ts = Get-Date -Format "HH:mm:ss"; Write-Host "[$ts] $Message" }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DefaultBackupDir {
  $ts = Get-Date -Format "yyyyMMdd-HHmmss"
  $root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
  return Join-Path $root "artifacts\backups\$env:COMPUTERNAME-$ts\splunk-forwarder"
}

function Probe-System {
  Write-Log "Probes: indexer connectivity"
  try {
    $tcp = Test-NetConnection -ComputerName $Indexer -Port $Port -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded) { Write-Log "Indexer reachable" } else { Write-Log "Indexer not reachable" }
  } catch {
    Write-Log "Test-NetConnection failed"
  }
}

function List-Status {
  $svc = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
  if ($svc) { $svc | Format-Table -AutoSize }
  $inputs = Join-Path $SplunkHome "etc\system\local\inputs.conf"
  if (Test-Path $inputs) { Get-Content $inputs }
}

function Plan-Changes {
  Write-Log "Planned changes"
  if (-not (Test-Path $SplunkHome)) { Write-Host "- Would install forwarder from $InstallerPath" }
  Write-Host "- Would configure forwarder to send to $Indexer:$Port"
  Write-Host "- Would set minimal inputs (Security/System event logs)"
}

function Backup-Configs {
  $dir = if ([string]::IsNullOrWhiteSpace($BackupDir)) { Get-DefaultBackupDir } else { $BackupDir }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $src = Join-Path $SplunkHome "etc\system\local"
  if (Test-Path $src) {
    Copy-Item -Recurse -Force $src (Join-Path $dir "local")
    Write-Log "Backup created in: $dir"
  } else {
    Write-Log "No forwarder config to back up"
  }
}

function Restore-Configs {
  if ([string]::IsNullOrWhiteSpace($RestoreFrom)) { throw "-RestoreFrom is required." }
  if (-not (Test-Path $RestoreFrom)) { throw "Restore path not found: $RestoreFrom" }
  $src = Join-Path $RestoreFrom "local"
  if (Test-Path $src) {
    Copy-Item -Recurse -Force $src (Join-Path $SplunkHome "etc\system\local")
    Write-Log "Restore applied from: $RestoreFrom"
  } else {
    Write-Log "No local config found in restore path"
  }
}

function Install-Forwarder {
  if (Test-Path $SplunkHome) { return }
  if ([string]::IsNullOrWhiteSpace($InstallerPath)) { throw "-InstallerPath is required." }
  if (-not (Test-Path $InstallerPath)) { throw "Installer not found: $InstallerPath" }
  if ([string]::IsNullOrWhiteSpace($SplunkPass)) { throw "-SplunkPass is required." }
  $args = @(
    "/i",
    "`"$InstallerPath`"",
    "AGREETOLICENSE=Yes",
    "SPLUNKUSERNAME=admin",
    "SPLUNKPASSWORD=$SplunkPass",
    "RECEIVING_INDEXER=$Indexer:$Port",
    "/qn"
  )
  Start-Process -FilePath msiexec.exe -ArgumentList $args -Wait
}

function Configure-Forwarder {
  $inputs = Join-Path $SplunkHome "etc\system\local\inputs.conf"
  New-Item -ItemType Directory -Force -Path (Split-Path $inputs) | Out-Null
  @"
[WinEventLog://Security]
index=maccdc
renderXml=false

[WinEventLog://System]
index=maccdc
renderXml=false
"@ | Out-File -FilePath $inputs -Encoding ASCII
  Restart-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
}

try {
  switch ($Mode) {
    "list" {
      Probe-System
      List-Status
    }
    "dry-run" {
      Probe-System
      Plan-Changes
    }
    "backup" {
      if (-not (Test-Admin)) { throw "This mode requires admin." }
      Backup-Configs
    }
    "restore" {
      if (-not (Test-Admin)) { throw "This mode requires admin." }
      Restore-Configs
    }
    "apply" {
      if (-not (Test-Admin)) { throw "This mode requires admin." }
      Probe-System
      Plan-Changes
      Backup-Configs
      Install-Forwarder
      Configure-Forwarder
    }
    default { throw "Unknown mode: $Mode" }
  }
} catch {
  Write-Error $_.Exception.Message
  exit 1
}
