<#
Compare-Procmon-COM.ps1
Usage:
  .\Compare-Procmon-COM.ps1 -ProcmonCsv "C:\Temp\procmon_export.csv" -ProcessName "inhouseapp.exe" -OutDir "C:\Temp\com_report"

Notes:
 - ProcMon must be exported to CSV (ProcMon -> File -> Save -> CSV). PML is not parsed by this script.
 - Run as Administrator to allow registry and ACL inspection.
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$ProcmonCsv,

  [string]$ProcessName = "inhouseapp.exe",

  [string]$OutDir = (Join-Path (Get-Location) "com_report")
)

# Prepare output directory
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory | Out-Null }

# Helper regex for GUID/CLSID
$guidRegex = '\{[0-9A-Fa-f\-]{36}\}'

# Load Procmon CSV
Write-Host "we executed: Importing ProcMon CSV..."
$pm = Import-Csv -Path $ProcmonCsv -ErrorAction Stop

# Normalize column names: try to find Operation, Process Name, Path columns
$opCol = ($pm | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name) | Where-Object { $_ -match '(?i)operation' } | Select-Object -First 1
$procCol = ($pm | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name) | Where-Object { $_ -match '(?i)process' } | Select-Object -First 1
$pathCol = ($pm | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name) | Where-Object { $_ -match '(?i)^path$|(?i)detail|(?i)result|(?i)path' } | Select-Object -First 1

if (-not $opCol -or -not $procCol -or -not $pathCol) {
  Write-Error "Could not identify required CSV columns (Operation, Process Name, Path). Check your ProcMon CSV format."
  exit 1
}

# Filter ProcMon entries for the target process and registry operations
Write-Host "we executed: Filtering ProcMon events for process '$ProcessName' and registry operations..."
$regOps = @('RegOpenKey','RegQueryValue','RegQueryValueEx','RegEnumKey','RegCreateKey','RegSetValue')
$events = $pm | Where-Object {
  ($_.$procCol -ieq $ProcessName) -and ($regOps -contains $_.$opCol)
}

# Extract referenced CLSIDs from Path/Detail columns
Write-Host "we executed: Extracting CLSIDs referenced by ProcMon events..."
$foundGuids = @()
foreach ($e in $events) {
  $text = ($_.$pathCol) -as [string]
  if ($text) {
    $matches = [regex]::Matches($text, $guidRegex)
    foreach ($m in $matches) { $foundGuids += $m.Value.ToUpper() }
  }
}
$foundGuids = $foundGuids | Sort-Object -Unique

# If none found, try searching for 'CLSID' text lines with a following GUID
if ($foundGuids.Count -eq 0) {
  Write-Host "no GUIDs found directly; searching lines containing 'CLSID'..."
  $lines = $events | ForEach-Object { ($_.$pathCol) -as [string] }
  foreach ($ln in $lines) {
    if ($ln -and $ln -match 'CLSID' -and ($ln -match $guidRegex)) {
      $foundGuids += ($Matches[0].Value.ToUpper())
    }
  }
  $foundGuids = $foundGuids | Sort-Object -Unique
}

# If still none, fall back to extracting any {GUID} tokens from the entire CSV for this process
if ($foundGuids.Count -eq 0) {
  Write-Host "no CLSIDs found in procmon filtered events; extracting any GUID tokens seen for the process..."
  $allText = ($events | ForEach-Object { ($_.$pathCol) -as [string] }) -join "`n"
  $matches = [regex]::Matches($allText, $guidRegex)
  foreach ($m in $matches) { $foundGuids += $m.Value.ToUpper() }
  $foundGuids = $foundGuids | Sort-Object -Unique
}

Write-Host "we executed: Found $($foundGuids.Count) unique GUID(s) referenced."

# Function to safe-get registry values
function Get-RegistryValueSafe {
  param($baseKey, $subKey, $valueName)
  try {
    $full = Join-Path $baseKey $subKey
    $v = (Get-ItemProperty -Path $full -Name $valueName -ErrorAction Stop).$valueName
    return $v
  } catch { return $null }
}

# Evaluate each CLSID by reading HKCR\CLSID\{guid}
$report = @()
foreach ($guid in $foundGuids) {
  $key = "Registry::HKCR\CLSID\$guid"
  $inproc = $null; $local = $null
  try {
    $inproc = (Get-ItemProperty -Path "$key\InprocServer32" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
  } catch {}
  try {
    $local = (Get-ItemProperty -Path "$key\LocalServer32" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
  } catch {}

  # Normalize empty strings
  if ($inproc -eq '') { $inproc = $null }
  if ($local -eq '') { $local = $null }

  # Determine suspiciousness
  $suspicious = $false
  $susReason = @()
  foreach ($p in @($inproc,$local)) {
    if ($p -and ($p -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|%APPDATA%|\\\\')) {
      $suspicious = $true
      $susReason += $p
    }
  }

  # Inspect file info if path present
  $filePath = $inproc -or $local
  $fileExists = $false; $fileHash = $null; $aclWritable = $null; $fileSize = $null
  if ($filePath) {
    # Trim possible command-line args and enclosing quotes
    $fp = $filePath.Trim()
    if ($fp -match '^"([^"]+)"') { $fp = $Matches[1] }
    if ($fp -match '^(?<p>[A-Za-z]:\\[^ ]+)') { $fp = $Matches['p'] }
    # If it starts with COM ProgID or CLSID then leave as-is
    if (Test-Path $fp) {
      $fileExists = $true
      try { $fileHash = (Get-FileHash -Path $fp -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $fileHash = $null }
      try { $fileSize = (Get-Item $fp).Length } catch { $fileSize = $null }
      # ACL writable test (non-destructive): try creating a temp file in parent dir
      try {
        $parent = Split-Path $fp -Parent
        $tempTest = Join-Path $parent ("poc_test_{0}.tmp" -f ([guid]::NewGuid().ToString()))
        New-Item -Path $tempTest -ItemType File -Force -ErrorAction Stop | Out-Null
        Remove-Item -Path $tempTest -Force -ErrorAction SilentlyContinue
        $aclWritable = $true
      } catch { $aclWritable = $false }
    }
  }

  # Registry ACL test
  $regAclWritable = $false
  try {
    $acl = Get-Acl -Path $key -ErrorAction Stop
    # If any non-admin identity has write access, mark writable
    foreach ($ace in $acl.Access) {
      $id = $ace.IdentityReference.Value
      if ($ace.FileSystemRights -match 'Write|Modify|FullControl' -and $id -match 'Users|Authenticated Users|Everyone|DOMAIN\\Users') {
        $regAclWritable = $true; break
      }
    }
  } catch { $regAclWritable = $null }

  $report += [PSCustomObject]@{
    CLSID = $guid
    InprocServer32 = $inproc
    LocalServer32 = $local
    ReferencedInProcmon = $true
    SuspiciousLocation = $suspicious
    SuspiciousExamples = ($susReason -join '; ')
    ServerFilePath = $filePath
    FileExists = $fileExists
    FileSize = $fileSize
    FileSHA256 = $fileHash
    FileParentWritable = $aclWritable
    RegistryACLWritable = $regAclWritable
  }
}

# If no GUIDs referenced, optionally attempt to map by ProgID values ProcMon captured
if ($report.Count -eq 0) {
  Write-Host "No CLSIDs matched. Looking for possible ProgIDs/COM strings in ProcMon events..."
  $textLines = ($events | ForEach-Object { ($_.$pathCol) -as [string] }) -join "`n"
  $progMatches = [regex]::Matches($textLines, '([A-Za-z0-9_.]+\.[A-Za-z0-9_.]+)') | ForEach-Object { $_.Value } | Sort-Object -Unique
  if ($progMatches.Count -gt 0) {
    foreach ($pid in $progMatches) {
      # try resolving ProgID -> CLSID
      try {
        $cls = (Get-ItemProperty -Path "HKCR:\$pid\CLSID" -ErrorAction SilentlyContinue).CLSID
        if ($cls) {
          # add similar entry as above
          $inproc = (Get-ItemProperty -Path "Registry::HKCR\CLSID\$cls\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
          $local = (Get-ItemProperty -Path "Registry::HKCR\CLSID\$cls\LocalServer32" -ErrorAction SilentlyContinue).'(default)'
          $report += [PSCustomObject]@{ CLSID=$cls; InprocServer32=$inproc; LocalServer32=$local; ReferencedInProcmon=$true; SuspiciousLocation=$false; SuspiciousExamples=''; ServerFilePath=($inproc -or $local); FileExists=(Test-Path ($inproc -or $local)); FileSHA256=''; FileParentWritable=$null; RegistryACLWritable=$null }
        }
      } catch {}
    }
  }
}

# Export reports
$summaryCsv = Join-Path $OutDir "com_summary.csv"
$detailsCsv = Join-Path $OutDir "com_details.csv"
$writableCsv = Join-Path $OutDir "com_writable_findings.csv"

$report | Export-Csv -Path $detailsCsv -NoTypeInformation
$report | Select-Object CLSID, ServerFilePath, FileExists, FileSHA256, FileParentWritable, RegistryACLWritable, SuspiciousLocation | Export-Csv -Path $summaryCsv -NoTypeInformation

$report | Where-Object { $_.FileParentWritable -eq $true -or $_.RegistryACLWritable -eq $true -or $_.SuspiciousLocation -eq $true } | Export-Csv -Path $writableCsv -NoTypeInformation

Write-Host "we executed: Reports written to:"
Write-Host " - $detailsCsv"
Write-Host " - $summaryCsv"
Write-Host " - $writableCsv"
Write-Host "Open $writableCsv first to review high-priority findings."
