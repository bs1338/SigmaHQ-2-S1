# file_event_win_susp_system_interactive_powershell

## Title
Suspicious Interactive PowerShell as SYSTEM

## ID
5b40a734-99b6-4b98-a1d0-1cea51a08ab2

## Author
Florian Roth (Nextron Systems)

## Date
2021-12-07

## Tags
attack.execution, attack.t1059.001

## Description
Detects the creation of files that indicator an interactive use of PowerShell in the SYSTEM user context

## References
https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PowerSploit_Invoke-Mimikatz.htm

## False Positives
Administrative activity
PowerShell scripts running as SYSTEM user

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath In Contains AnyCase ("C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt","C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive")))

```