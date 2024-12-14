# file_event_win_sysinternals_procmon_driver_susp_creation

## Title
Process Monitor Driver Creation By Non-Sysinternals Binary

## ID
a05baa88-e922-4001-bc4d-8738135f27de

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-05

## Tags
attack.persistence, attack.privilege-escalation, attack.t1068

## Description
Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself.

## References
Internal Research

## False Positives
Some false positives may occur with legitimate renamed process monitor binaries

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\procmon" AND TgtFilePath endswithCIS ".sys") AND (NOT (SrcProcImagePath endswithCIS "\procmon.exe" OR SrcProcImagePath endswithCIS "\procmon64.exe"))))

```