# proc_creation_win_rar_compress_data

## Title
Files Added To An Archive Using Rar.EXE

## ID
6f3e2987-db24-4c78-a860-b4f4095a7095

## Author
Timur Zinniatullin, E.M. Anhaus, oscd.community

## Date
2019-10-21

## Tags
attack.collection, attack.t1560.001

## Description
Detects usage of "rar" to add files to an archive for potential compression. An adversary may compress data (e.g. sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
https://eqllib.readthedocs.io/en/latest/analytics/1ec33c93-3d0b-4a28-8014-dbdaae5c60ae.html

## False Positives
Highly likely if rar is a default archiver in the monitored environment.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " a " AND TgtProcImagePath endswithCIS "\rar.exe"))

```