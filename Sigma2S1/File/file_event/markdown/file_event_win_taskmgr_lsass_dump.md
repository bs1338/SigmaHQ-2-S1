# file_event_win_taskmgr_lsass_dump

## Title
LSASS Process Memory Dump Creation Via Taskmgr.EXE

## ID
69ca12af-119d-44ed-b50f-a47af0ebc364

## Author
Swachchhanda Shrawan Poudel

## Date
2023-10-19

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the creation of an "lsass.dmp" file by the taskmgr process. This indicates a manual dumping of the LSASS.exe process memory using Windows Task Manager.

## References
https://github.com/redcanaryco/atomic-red-team/blob/987e3ca988ae3cff4b9f6e388c139c05bf44bbb8/atomics/T1003.001/T1003.001.md#L1

## False Positives
Rare case of troubleshooting by an administrator or support that has to be investigated regardless

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS ":\Windows\system32\taskmgr.exe" OR SrcProcImagePath endswithCIS ":\Windows\SysWOW64\taskmgr.exe") AND (TgtFilePath containsCIS "\AppData\Local\Temp\" AND TgtFilePath containsCIS "\lsass" AND TgtFilePath containsCIS ".DMP")))

```