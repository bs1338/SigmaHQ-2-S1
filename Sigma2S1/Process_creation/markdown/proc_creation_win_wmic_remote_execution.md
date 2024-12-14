# proc_creation_win_wmic_remote_execution

## Title
WMIC Remote Command Execution

## ID
7773b877-5abb-4a3e-b9c9-fd0369b59b00

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-14

## Tags
attack.execution, attack.t1047

## Description
Detects the execution of WMIC to query information on a remote system

## References
https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/node:" AND TgtProcImagePath endswithCIS "\WMIC.exe") AND (NOT (TgtProcCmdLine containsCIS "/node:127.0.0.1 " OR TgtProcCmdLine containsCIS "/node:localhost "))))

```