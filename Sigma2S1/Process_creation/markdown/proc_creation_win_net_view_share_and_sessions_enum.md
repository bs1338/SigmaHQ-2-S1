# proc_creation_win_net_view_share_and_sessions_enum

## Title
Share And Session Enumeration Using Net.EXE

## ID
62510e69-616b-4078-b371-847da438cc03

## Author
Endgame, JHasenbusch (ported for oscd.community)

## Date
2018-10-30

## Tags
attack.discovery, attack.t1018

## Description
Detects attempts to enumerate file shares, printer shares and sessions using "net.exe" with the "view" flag.

## References
https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md

## False Positives
Legitimate use of net.exe utility by legitimate user

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "view" AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")) AND (NOT TgtProcCmdLine containsCIS "\\")))

```