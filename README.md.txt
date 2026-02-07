# Windows Event Log Threat Hunter (Python)

Parses exported Windows Security logs (CSV) and produces a SOC-style summary.

## Features
- Counts successful (4624) and failed (4625) logons
- Burst detection for failed logons (brute-force indicator)
- Password-spray indicator (one IP targeting many usernames)
- Summary of logon types and top source IPs (4624)

## Export logs (PowerShell, run as Administrator)
```powershell
$since = (Get-Date).AddHours(-24)
$out = Join-Path $env:USERPROFILE "Documents\security_logins_24h.csv"
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4624; StartTime=$since} |
Select-Object TimeCreated, Id, MachineName, Message |
Export-Csv -NoTypeInformation -Encoding UTF8 $out
Write-Host "Saved to: $out"