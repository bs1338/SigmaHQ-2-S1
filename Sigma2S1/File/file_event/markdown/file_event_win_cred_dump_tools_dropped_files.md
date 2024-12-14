# file_event_win_cred_dump_tools_dropped_files

## Title
Cred Dump Tools Dropped Files

## ID
8fbf3271-1ef6-4e94-8210-03c2317947f6

## Author
Teymur Kheirkhabarov, oscd.community

## Date
2019-11-01

## Tags
attack.credential-access, attack.t1003.001, attack.t1003.002, attack.t1003.003, attack.t1003.004, attack.t1003.005

## Description
Files with well-known filenames (parts of credential dump software or files produced by them) creation

## References
https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

## False Positives
Legitimate Administrator using tool for password recovery

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\fgdump-log" OR TgtFilePath containsCIS "\kirbi" OR TgtFilePath containsCIS "\pwdump" OR TgtFilePath containsCIS "\pwhashes" OR TgtFilePath containsCIS "\wce_ccache" OR TgtFilePath containsCIS "\wce_krbtkts") OR (TgtFilePath endswithCIS "\cachedump.exe" OR TgtFilePath endswithCIS "\cachedump64.exe" OR TgtFilePath endswithCIS "\DumpExt.dll" OR TgtFilePath endswithCIS "\DumpSvc.exe" OR TgtFilePath endswithCIS "\Dumpy.exe" OR TgtFilePath endswithCIS "\fgexec.exe" OR TgtFilePath endswithCIS "\lsremora.dll" OR TgtFilePath endswithCIS "\lsremora64.dll" OR TgtFilePath endswithCIS "\NTDS.out" OR TgtFilePath endswithCIS "\procdump64.exe" OR TgtFilePath endswithCIS "\pstgdump.exe" OR TgtFilePath endswithCIS "\pwdump.exe" OR TgtFilePath endswithCIS "\SAM.out" OR TgtFilePath endswithCIS "\SECURITY.out" OR TgtFilePath endswithCIS "\servpw.exe" OR TgtFilePath endswithCIS "\servpw64.exe" OR TgtFilePath endswithCIS "\SYSTEM.out" OR TgtFilePath endswithCIS "\test.pwd" OR TgtFilePath endswithCIS "\wceaux.dll")))

```