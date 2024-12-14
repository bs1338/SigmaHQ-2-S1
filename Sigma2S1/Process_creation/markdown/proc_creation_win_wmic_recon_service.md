# proc_creation_win_wmic_recon_service

## Title
Service Reconnaissance Via Wmic.EXE

## ID
76f55eaa-d27f-4213-9d45-7b0e4b60bbae

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-14

## Tags
attack.execution, attack.t1047

## Description
An adversary might use WMI to check if a certain remote service is running on a remote device.
When the test completes, a service information will be displayed on the screen if it exists.
A common feedback message is that "No instance(s) Available" if the service queried is not running.
A common error message is "Node - (provided IP or default) ERROR Description =The RPC server is unavailable" if the provided remote host is unreachable


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "service" AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```