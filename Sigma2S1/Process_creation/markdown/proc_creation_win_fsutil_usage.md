# proc_creation_win_fsutil_usage

## Title
Fsutil Suspicious Invocation

## ID
add64136-62e5-48ea-807e-88638d02df1e

## Author
Ecco, E.M. Anhaus, oscd.community

## Date
2019-09-26

## Tags
attack.defense-evasion, attack.impact, attack.t1070, attack.t1485

## Description
Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size, etc).
Might be used by ransomwares during the attack (seen by NotPetya and others).


## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070/T1070.md
https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html
https://github.com/albertzsigovits/malware-notes/blob/558898932c1579ff589290092a2c8febefc3a4c9/Ransomware/Lockbit.md
https://blog.cluster25.duskrise.com/2023/05/22/back-in-black-blackbyte-nt

## False Positives
Admin activity
Scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "deletejournal" OR TgtProcCmdLine containsCIS "createjournal" OR TgtProcCmdLine containsCIS "setZeroData") AND TgtProcImagePath endswithCIS "\fsutil.exe"))

```