# proc_creation_win_powershell_sam_access

## Title
PowerShell SAM Copy

## ID
1af57a4b-460a-4738-9034-db68b880c665

## Author
Florian Roth (Nextron Systems)

## Date
2021-07-29

## Tags
attack.credential-access, attack.t1003.002

## Description
Detects suspicious PowerShell scripts accessing SAM hives

## References
https://twitter.com/splinter_code/status/1420546784250769408

## False Positives
Some rare backup scenarios
PowerShell scripts fixing HiveNightmare / SeriousSAM ACLs

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\HarddiskVolumeShadowCopy" AND TgtProcCmdLine containsCIS "System32\config\sam") AND (TgtProcCmdLine containsCIS "Copy-Item" OR TgtProcCmdLine containsCIS "cp $_." OR TgtProcCmdLine containsCIS "cpi $_." OR TgtProcCmdLine containsCIS "copy $_." OR TgtProcCmdLine containsCIS ".File]::Copy(")))

```