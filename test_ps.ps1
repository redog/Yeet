$ErrorActionPreference = 'Stop'
$tempKeyPath = [System.IO.Path]::GetTempFileName()
Copy-Item "test_key5" -Destination $tempKeyPath -Force
ssh-keygen -p -f $tempKeyPath -N ""
Get-Content $tempKeyPath | Select-Object -First 3
Remove-Item $tempKeyPath
