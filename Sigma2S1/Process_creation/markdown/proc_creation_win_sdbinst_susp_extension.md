# proc_creation_win_sdbinst_susp_extension

## Title
Uncommon Extension Shim Database Installation Via Sdbinst.EXE

## ID
18ee686c-38a3-4f65-9f44-48a077141f42

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-01

## Tags
attack.persistence, attack.privilege-escalation, attack.t1546.011

## Description
Detects installation of a potentially suspicious new shim with an uncommon extension using sdbinst.exe.
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims


## References
https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
https://github.com/nasbench/Misc-Research/blob/8ee690e43a379cbce8c9d61107442c36bd9be3d3/Other/Undocumented-Flags-Sdbinst.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\sdbinst.exe" AND (NOT (TgtProcCmdLine = "" OR TgtProcCmdLine containsCIS ".sdb" OR ((TgtProcCmdLine endswithCIS " -c" OR TgtProcCmdLine endswithCIS " -f" OR TgtProcCmdLine endswithCIS " -mm" OR TgtProcCmdLine endswithCIS " -t") OR TgtProcCmdLine containsCIS " -m -bg") OR TgtProcCmdLine IS NOT EMPTY))))

```