# proc_creation_win_regedit_trustedinstaller

## Title
Regedit as Trusted Installer

## ID
883835a7-df45-43e4-bf1d-4268768afda4

## Author
Florian Roth (Nextron Systems)

## Date
2021-05-27

## Tags
attack.privilege-escalation, attack.t1548

## Description
Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe

## References
https://twitter.com/1kwpeter/status/1397816101455765504

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\regedit.exe" AND (SrcProcImagePath endswithCIS "\TrustedInstaller.exe" OR SrcProcImagePath endswithCIS "\ProcessHacker.exe")))

```