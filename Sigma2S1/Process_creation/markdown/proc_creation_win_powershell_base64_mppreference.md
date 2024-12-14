# proc_creation_win_powershell_base64_mppreference

## Title
Powershell Base64 Encoded MpPreference Cmdlet

## ID
c6fb44c6-71f5-49e6-9462-1425d328aee3

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-04

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects base64 encoded "MpPreference" PowerShell cmdlet code that tries to modifies or tamper with Windows Defender AV

## References
https://learn.microsoft.com/en-us/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
https://twitter.com/AdamTheAnalyst/status/1483497517119590403

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "QWRkLU1wUHJlZmVyZW5jZS" OR TgtProcCmdLine containsCIS "FkZC1NcFByZWZlcmVuY2Ug" OR TgtProcCmdLine containsCIS "BZGQtTXBQcmVmZXJlbmNlI" OR TgtProcCmdLine containsCIS "U2V0LU1wUHJlZmVyZW5jZS" OR TgtProcCmdLine containsCIS "NldC1NcFByZWZlcmVuY2Ug" OR TgtProcCmdLine containsCIS "TZXQtTXBQcmVmZXJlbmNlI" OR TgtProcCmdLine containsCIS "YWRkLW1wcHJlZmVyZW5jZS" OR TgtProcCmdLine containsCIS "FkZC1tcHByZWZlcmVuY2Ug" OR TgtProcCmdLine containsCIS "hZGQtbXBwcmVmZXJlbmNlI" OR TgtProcCmdLine containsCIS "c2V0LW1wcHJlZmVyZW5jZS" OR TgtProcCmdLine containsCIS "NldC1tcHByZWZlcmVuY2Ug" OR TgtProcCmdLine containsCIS "zZXQtbXBwcmVmZXJlbmNlI") OR (TgtProcCmdLine containsCIS "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA" OR TgtProcCmdLine containsCIS "EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA" OR TgtProcCmdLine containsCIS "BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA" OR TgtProcCmdLine containsCIS "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA" OR TgtProcCmdLine containsCIS "MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA" OR TgtProcCmdLine containsCIS "TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA" OR TgtProcCmdLine containsCIS "YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA" OR TgtProcCmdLine containsCIS "EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA" OR TgtProcCmdLine containsCIS "hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA" OR TgtProcCmdLine containsCIS "cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA" OR TgtProcCmdLine containsCIS "MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA" OR TgtProcCmdLine containsCIS "zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA")))

```