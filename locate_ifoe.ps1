# List IFEO keys (HKLM) including Wow6432Node
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
  ForEach-Object {
    $exe = $_.PSChildName
    $dbg = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
    [PSCustomObject]@{Executable=$exe; Debugger=$dbg; RegistryPath=$_.PSPath}
  } | Where-Object { $_.Debugger -ne $null } | Format-Table -AutoSize
# Repeat for Wow6432Node (32-bit)
Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
  ForEach-Object {
    $exe = $_.PSChildName
    $dbg = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
    [PSCustomObject]@{Executable=$exe; Debugger=$dbg; RegistryPath=$_.PSPath}
  } | Where-Object { $_.Debugger -ne $null } | Format-Table -AutoSize
