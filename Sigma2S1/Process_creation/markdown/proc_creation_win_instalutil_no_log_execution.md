# proc_creation_win_instalutil_no_log_execution

## Title
Suspicious Execution of InstallUtil Without Log

## ID
d042284c-a296-4988-9be5-f424fadcc28c

## Author
frack113

## Date
2022-01-23

## Tags
attack.defense-evasion

## Description
Uses the .NET InstallUtil.exe application in order to execute image without log

## References
https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/logfile= " AND TgtProcCmdLine containsCIS "/LogToConsole=false") AND TgtProcImagePath containsCIS "Microsoft.NET\Framework" AND TgtProcImagePath endswithCIS "\InstallUtil.exe"))

```