# proc_creation_win_schtasks_one_time_only_midnight_task

## Title
Uncommon One Time Only Scheduled Task At 00:00

## ID
970823b7-273b-460a-8afc-3a6811998529

## Author
pH-T (Nextron Systems)

## Date
2022-07-15

## Tags
attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005

## Description
Detects scheduled task creation events that include suspicious actions, and is run once at 00:00

## References
https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte

## False Positives
Software installation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "vbscript" OR TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "wmic " OR TgtProcCmdLine containsCIS "wmic.exe" OR TgtProcCmdLine containsCIS "regsvr32.exe" OR TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "\AppData\") AND TgtProcImagePath containsCIS "\schtasks.exe" AND (TgtProcCmdLine containsCIS "once" AND TgtProcCmdLine containsCIS "00:00")))

```