# proc_creation_win_susp_appx_execution

## Title
Potentially Suspicious Windows App Activity

## ID
f91ed517-a6ba-471d-9910-b3b4a398c0f3

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-12

## Tags
attack.defense-evasion

## Description
Detects potentially suspicious child process of applications launched from inside the WindowsApps directory. This could be a sign of a rogue ".appx" package installation/execution

## References
https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/

## False Positives
Legitimate packages that make use of external binaries such as Windows Terminal

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath containsCIS "C:\Program Files\WindowsApps\" AND ((TgtProcCmdLine containsCIS "cmd /c" OR TgtProcCmdLine containsCIS "Invoke-" OR TgtProcCmdLine containsCIS "Base64") OR (TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe")) AND (NOT ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND SrcProcImagePath containsCIS ":\Program Files\WindowsApps\Microsoft.WindowsTerminal" AND SrcProcImagePath endswithCIS "\WindowsTerminal.exe"))))

```