<#
Usage:
  .\check-mitigations.ps1 -Path "C:\Program Files\InHouseApp" 

What it does:
 - scans *.exe and *.dll under the Path
 - reads the PE OptionalHeader.DllCharacteristics bits using System.Reflection.Metadata.PEReader
 - prints human-readable flags: ASLR (DynamicBase), NX (NXCompat), CFG (GuardCF), NoSEH, AppContainer, HighEntropyVA
 - flags managed (.NET) assemblies (CLI header present)
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$Path
)

# Helper: maps bit flags to names (values from Windows IMAGE_DLLCHARACTERISTICS)
$flagMap = @{
  0x0020 = 'HighEntropyVA'
  0x0040 = 'DynamicBase (ASLR)'
  0x0080 = 'ForceIntegrity'
  0x0100 = 'NXCompat (DEP/NX)'
  0x0200 = 'NoIsolation'
  0x0400 = 'NoSEH'
  0x0800 = 'NoBind'
  0x1000 = 'AppContainer'
  0x2000 = 'WDMDriver'
  0x4000 = 'GuardCF (Control Flow Guard)'
  0x8000 = 'TerminalServerAware'
}

Add-Type -AssemblyName System.Reflection.Metadata -ErrorAction Stop

function Get-PeDllCharacteristics {
  param([string]$file)
  try {
    $fs = [System.IO.File]::OpenRead($file)
    $pe = [System.Reflection.PortableExecutable.PEReader]::new($fs)
    $hdr = $pe.PEHeaders
    if (-not $hdr) { $pe.Dispose(); $fs.Close(); return $null }
    $dllChars = $hdr.OptionalHeader.DllCharacteristics
    $isCli = $null -ne $hdr.CorHeader
    $pe.Dispose()
    $fs.Close()
    return [PSCustomObject]@{
      File = $file
      IsManaged = $isCli
      DllCharacteristics = $dllChars
    }
  } catch {
    Write-Warning "Failed to parse $file : $_"
    return $null
  }
}

function Format-Flags {
  param($value)
  $present = @()
  foreach ($bit in $flagMap.Keys | Sort-Object) {
    if ($value -band $bit) { $present += $flagMap[$bit] }
  }
  if ($present.Count -eq 0) { return "NONE" }
  return $present -join ', '
}

# Walk files
$files = Get-ChildItem -Path $Path -Include *.exe,*.dll -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
if (-not $files) { Write-Host "No .exe/.dll found under $Path"; exit 0 }

$report = foreach ($f in $files) {
  $r = Get-PeDllCharacteristics -file $f
  if ($r -eq $null) { continue }
  [PSCustomObject]@{
    File = $r.File
    Managed = $r.IsManaged
    DllCharacteristicsValue = ("0x{0:X}" -f $r.DllCharacteristics)
    Flags = (Format-Flags $r.DllCharacteristics)
  }
}

# Pretty output and save CSV
$report | Format-Table -AutoSize
$csv = Join-Path -Path (Get-Location) -ChildPath "pe_mitigations_report.csv"
$report | Export-Csv -Path $csv -NoTypeInformation
Write-Host "`nReport exported to: $csv"
