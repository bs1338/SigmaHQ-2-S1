# proc_creation_win_lolbin_diantz_remote_cab

## Title
Suspicious Diantz Download and Compress Into a CAB File

## ID
185d7418-f250-42d0-b72e-0c8b70661e93

## Author
frack113

## Date
2021-11-26

## Tags
attack.command-and-control, attack.t1105

## Description
Download and compress a remote file and store it in a cab file on local machine.

## References
https://lolbas-project.github.io/lolbas/Binaries/Diantz/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "diantz.exe" AND TgtProcCmdLine containsCIS " \\" AND TgtProcCmdLine containsCIS ".cab"))

```