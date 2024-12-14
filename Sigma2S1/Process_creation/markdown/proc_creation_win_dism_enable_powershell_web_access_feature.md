# proc_creation_win_dism_enable_powershell_web_access_feature

## Title
PowerShell Web Access Feature Enabled Via DISM

## ID
7e8f2d3b-9c1a-4f67-b9e8-8d9006e0e51f

## Author
Michael Haag

## Date
2024-09-03

## Tags
attack.persistence, attack.t1548.002

## Description
Detects the use of DISM to enable the PowerShell Web Access feature, which could be used for remote access and potential abuse

## References
https://docs.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature
https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
https://gist.github.com/MHaggis/7e67b659af9148fa593cf2402edebb41

## False Positives
Legitimate PowerShell Web Access installations by administrators

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "WindowsPowerShellWebAccess" AND TgtProcCmdLine containsCIS "/online" AND TgtProcCmdLine containsCIS "/enable-feature") AND TgtProcImagePath endswithCIS "\dism.exe"))

```