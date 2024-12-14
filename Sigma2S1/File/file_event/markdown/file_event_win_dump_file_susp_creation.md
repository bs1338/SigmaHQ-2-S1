# file_event_win_dump_file_susp_creation

## Title
Potentially Suspicious DMP/HDMP File Creation

## ID
aba15bdd-657f-422a-bab3-ac2d2a0d6f1c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-07

## Tags
attack.defense-evasion

## Description
Detects the creation of a file with the ".dmp"/".hdmp" extension by a shell or scripting application such as "cmd", "powershell", etc. Often created by software during a crash. Memory dumps can sometimes contain sensitive information such as credentials. It's best to determine the source of the crash.

## References
https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps

## False Positives
Some administrative PowerShell or VB scripts might have the ability to collect dumps and move them to other folders which might trigger a false positive.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\wscript.exe") AND (TgtFilePath endswithCIS ".dmp" OR TgtFilePath endswithCIS ".dump" OR TgtFilePath endswithCIS ".hdmp")))

```