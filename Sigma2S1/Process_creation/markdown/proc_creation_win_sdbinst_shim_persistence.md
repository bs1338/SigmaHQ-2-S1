# proc_creation_win_sdbinst_shim_persistence

## Title
Potential Shim Database Persistence via Sdbinst.EXE

## ID
517490a7-115a-48c6-8862-1a481504d5a8

## Author
Markus Neis

## Date
2019-01-16

## Tags
attack.persistence, attack.privilege-escalation, attack.t1546.011

## Description
Detects installation of a new shim using sdbinst.exe.
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims


## References
https://www.mandiant.com/resources/blog/fin7-shim-databases-persistence

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".sdb" AND TgtProcImagePath endswithCIS "\sdbinst.exe") AND (NOT ((TgtProcCmdLine containsCIS ":\Program Files (x86)\IIS Express\iisexpressshim.sdb" OR TgtProcCmdLine containsCIS ":\Program Files\IIS Express\iisexpressshim.sdb") AND SrcProcImagePath endswithCIS "\msiexec.exe"))))

```