# proc_creation_win_powercfg_execution

## Title
Suspicious Powercfg Execution To Change Lock Screen Timeout

## ID
f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b

## Author
frack113

## Date
2022-11-18

## Tags
attack.defense-evasion

## Description
Detects suspicious execution of 'Powercfg.exe' to change lock screen timeout

## References
https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\powercfg.exe" AND ((TgtProcCmdLine containsCIS "/setacvalueindex " AND TgtProcCmdLine containsCIS "SCHEME_CURRENT" AND TgtProcCmdLine containsCIS "SUB_VIDEO" AND TgtProcCmdLine containsCIS "VIDEOCONLOCK") OR (TgtProcCmdLine containsCIS "-change " AND TgtProcCmdLine containsCIS "-standby-timeout-"))))

```