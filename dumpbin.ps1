param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

function Get-DllCharacteristics {
    param([string]$FilePath)

    try {
        $fs = [System.IO.File]::Open($FilePath, 'Open', 'Read')
        $br = New-Object System.IO.BinaryReader($fs)

        # Check MZ header
        $mz = $br.ReadUInt16()
        if ($mz -ne 0x5A4D) { $br.Close(); $fs.Close(); return $null }  # Not PE

        # Move to PE header offset
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOffset = $br.ReadUInt32()

        # Move to PE signature
        $fs.Seek($peOffset, 'Begin') | Out-Null
        $peSig = $br.ReadUInt32()
        if ($peSig -ne 0x00004550) { $br.Close(); $fs.Close(); return $null }  # Not PE

        # Skip COFF header (20 bytes), then Optional Header standard fields (96 for PE32+, 92 for PE32)
        $fs.Seek(20, 'Current') | Out-Null
        $machine = $br.ReadUInt16()
        $fs.Seek(2, 'Current') | Out-Null   # Number of sections
        $fs.Seek(12, 'Current') | Out-Null  # Skip timestamps etc.
        $optHeaderSize = $br.ReadUInt16()
        $fs.Seek(2, 'Current') | Out-Null   # Characteristics

        $magic = $br.ReadUInt16()
        if ($magic -eq 0x20B) {
            # PE32+ (64-bit) → DLLCharacteristics at offset 0x5E
            $fs.Seek($peOffset + 0x88, 'Begin') | Out-Null
        } else {
            # PE32 (32-bit) → DLLCharacteristics at offset 0x5E
            $fs.Seek($peOffset + 0x5E, 'Begin') | Out-Null
        }
        $dllChars = $br.ReadUInt16()

        $br.Close()
        $fs.Close()
        return $dllChars
    } catch {
        return $null
    }
}

# Map bits to mitigation names
$flagMap = @{
    0x0040 = 'ASLR (DynamicBase)'
    0x0100 = 'DEP (NXCompat)'
    0x0400 = 'SafeSEH (x86 only)'
    0x4000 = 'CFG (Control Flow Guard)'
    0x0020 = 'HighEntropyVA'
    0x1000 = 'AppContainer'
}

function Format-Flags {
    param([UInt16]$val)
    $flags = @()
    foreach ($bit in $flagMap.Keys | Sort-Object) {
        if ($val -band $bit) { $flags += $flagMap[$bit] }
    }
    if ($flags.Count -eq 0) { return "NONE" }
    return $flags -join ", "
}

# Walk through all .exe and .dll in folder
$files = Get-ChildItem -Path $Path -Include *.exe,*.dll -Recurse -ErrorAction SilentlyContinue

$report = foreach ($f in $files) {
    $val = Get-DllCharacteristics $f.FullName
    if ($val -eq $null) { continue }
    [PSCustomObject]@{
        File = $f.FullName
        DllCharHex = ("0x{0:X}" -f $val)
        Flags = (Format-Flags $val)
    }
}

$report | Format-Table -AutoSize

$csv = Join-Path (Get-Location) "weak_memory_protection_report.csv"
$report | Export-Csv -Path $csv -NoTypeInformation
Write-Host "`nReport saved to $csv"
