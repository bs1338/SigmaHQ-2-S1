# proc_creation_win_lolbin_sftp

## Title
Use Of The SFTP.EXE Binary As A LOLBIN

## ID
a85ffc3a-e8fd-4040-93bf-78aff284d801

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-11-10

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects the usage of the "sftp.exe" binary as a LOLBIN by abusing the "-D" flag

## References
https://github.com/LOLBAS-Project/LOLBAS/pull/264

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -D .." OR TgtProcCmdLine containsCIS " -D C:\") AND TgtProcImagePath endswithCIS "\sftp.exe"))

```