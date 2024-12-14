# proc_creation_win_lolbin_remote

## Title
Use of Remote.exe

## ID
4eddc365-79b4-43ff-a9d7-99422dc34b93

## Author
Christopher Peacock @SecurePeacock, SCYTHE @scythe_io

## Date
2022-06-02

## Tags
attack.defense-evasion, attack.t1127

## Description
Remote.exe is part of WinDbg in the Windows SDK and can be used for AWL bypass and running remote files.

## References
https://blog.thecybersecuritytutor.com/Exeuction-AWL-Bypass-Remote-exe-LOLBin/
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Remote/

## False Positives
Approved installs of Windows SDK with Debugging Tools for Windows (WinDbg).

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\remote.exe")

```