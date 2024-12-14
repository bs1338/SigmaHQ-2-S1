# proc_creation_win_susp_eventlog_clear

## Title
Suspicious Eventlog Clearing or Configuration Change Activity

## ID
cc36992a-4671-4f21-a91d-6c2b72a2edf5

## Author
Ecco, Daniil Yugoslavskiy, oscd.community, D3F7A5105

## Date
2019-09-26

## Tags
attack.defense-evasion, attack.t1070.001, attack.t1562.002, car.2016-04-002

## Description
Detects the clearing or configuration tampering of EventLog using utilities such as "wevtutil", "powershell" and "wmic".
This technique were seen used by threat actors and ransomware strains in order to evade defenses.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.001/T1070.001.md
https://eqllib.readthedocs.io/en/latest/analytics/5b223758-07d6-4100-9e11-238cfdd0fe97.html
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
https://gist.github.com/fovtran/ac0624983c7722e80a8f5a4babb170ee
https://jdhnet.wordpress.com/2017/12/19/changing-the-location-of-the-windows-event-logs/

## False Positives
Admin activity
Scripts and administrative tools used in the monitored environment
Maintenance activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcCmdLine containsCIS "Clear-EventLog " OR TgtProcCmdLine containsCIS "Remove-EventLog " OR TgtProcCmdLine containsCIS "Limit-EventLog " OR TgtProcCmdLine containsCIS "Clear-WinEvent ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) OR (TgtProcCmdLine containsCIS "ClearEventLog" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wmic.exe")) OR ((TgtProcCmdLine containsCIS "clear-log " OR TgtProcCmdLine containsCIS " cl " OR TgtProcCmdLine containsCIS "set-log " OR TgtProcCmdLine containsCIS " sl " OR TgtProcCmdLine containsCIS "lfn:") AND TgtProcImagePath endswithCIS "\wevtutil.exe")) AND (NOT (TgtProcCmdLine containsCIS " sl " AND (SrcProcImagePath In Contains AnyCase ("C:\Windows\SysWOW64\msiexec.exe","C:\Windows\System32\msiexec.exe"))))))

```