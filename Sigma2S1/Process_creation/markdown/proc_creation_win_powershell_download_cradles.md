# proc_creation_win_powershell_download_cradles

## Title
PowerShell Web Download

## ID
6e897651-f157-4d8f-aaeb-df8151488385

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-24

## Tags
attack.command-and-control, attack.execution, attack.t1059.001, attack.t1105

## Description
Detects suspicious ways to download files or content using PowerShell

## References
https://github.com/VirtualAlllocEx/Payload-Download-Cradles/blob/88e8eca34464a547c90d9140d70e9866dcbc6a12/Download-Cradles.cmd

## False Positives
Scripts or tools that download files

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ".DownloadString(" OR TgtProcCmdLine containsCIS ".DownloadFile(" OR TgtProcCmdLine containsCIS "Invoke-WebRequest " OR TgtProcCmdLine containsCIS "iwr "))

```