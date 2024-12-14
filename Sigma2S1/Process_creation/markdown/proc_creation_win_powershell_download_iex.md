# proc_creation_win_powershell_download_iex

## Title
PowerShell Download and Execution Cradles

## ID
85b0b087-eddf-4a2b-b033-d771fa2b9775

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-24

## Tags
attack.execution, attack.t1059

## Description
Detects PowerShell download and execution cradles.

## References
https://github.com/VirtualAlllocEx/Payload-Download-Cradles/blob/88e8eca34464a547c90d9140d70e9866dcbc6a12/Download-Cradles.cmd
https://labs.withsecure.com/publications/fin7-target-veeam-servers

## False Positives
Some PowerShell installers were seen using similar combinations. Apply filters accordingly

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".DownloadString(" OR TgtProcCmdLine containsCIS ".DownloadFile(" OR TgtProcCmdLine containsCIS "Invoke-WebRequest " OR TgtProcCmdLine containsCIS "iwr ") AND (TgtProcCmdLine containsCIS ";iex $" OR TgtProcCmdLine containsCIS "| IEX" OR TgtProcCmdLine containsCIS "|IEX " OR TgtProcCmdLine containsCIS "I`E`X" OR TgtProcCmdLine containsCIS "I`EX" OR TgtProcCmdLine containsCIS "IE`X" OR TgtProcCmdLine containsCIS "iex " OR TgtProcCmdLine containsCIS "IEX (" OR TgtProcCmdLine containsCIS "IEX(" OR TgtProcCmdLine containsCIS "Invoke-Expression")))

```