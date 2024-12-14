# proc_creation_win_net_user_add

## Title
New User Created Via Net.EXE

## ID
cd219ff3-fa99-45d4-8380-a7d15116c6dc

## Author
Endgame, JHasenbusch (adapted to Sigma for oscd.community)

## Date
2018-10-30

## Tags
attack.persistence, attack.t1136.001

## Description
Identifies the creation of local users via the net.exe command.

## References
https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.001/T1136.001.md

## False Positives
Legitimate user creation.
Better use event IDs for user creation rather than command line rules.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "user" AND TgtProcCmdLine containsCIS "add") AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```