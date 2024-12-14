# proc_creation_win_susp_disable_raccine

## Title
Raccine Uninstall

## ID
a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc

## Author
Florian Roth (Nextron Systems)

## Date
2021-01-21

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.

## References
https://github.com/Neo23x0/Raccine

## False Positives
Legitimate deinstallation by administrative staff

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "taskkill " AND TgtProcCmdLine containsCIS "RaccineSettings.exe") OR (TgtProcCmdLine containsCIS "reg.exe" AND TgtProcCmdLine containsCIS "delete" AND TgtProcCmdLine containsCIS "Raccine Tray") OR (TgtProcCmdLine containsCIS "schtasks" AND TgtProcCmdLine containsCIS "/DELETE" AND TgtProcCmdLine containsCIS "Raccine Rules Updater")))

```