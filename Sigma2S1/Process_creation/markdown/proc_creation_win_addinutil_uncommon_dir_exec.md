# proc_creation_win_addinutil_uncommon_dir_exec

## Title
AddinUtil.EXE Execution From Uncommon Directory

## ID
6120ac2a-a34b-42c0-a9bd-1fb9f459f348

## Author
Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)

## Date
2023-09-18

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) from a non-standard directory.

## References
https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\addinutil.exe" AND (NOT (TgtProcImagePath containsCIS ":\Windows\Microsoft.NET\Framework\" OR TgtProcImagePath containsCIS ":\Windows\Microsoft.NET\Framework64\" OR TgtProcImagePath containsCIS ":\Windows\WinSxS\"))))

```