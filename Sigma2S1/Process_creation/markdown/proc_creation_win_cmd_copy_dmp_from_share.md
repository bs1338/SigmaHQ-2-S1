# proc_creation_win_cmd_copy_dmp_from_share

## Title
Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE

## ID
044ba588-dff4-4918-9808-3f95e8160606

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-27

## Tags
attack.credential-access

## Description
Detects usage of the copy builtin cmd command to copy files with the ".dmp"/".dump" extension from a remote share

## References
https://thedfirreport.com/2022/09/26/bumblebee-round-two/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS ".dmp" OR TgtProcCmdLine containsCIS ".dump" OR TgtProcCmdLine containsCIS ".hdmp") AND (TgtProcCmdLine containsCIS "copy " AND TgtProcCmdLine containsCIS " \\")) AND TgtProcImagePath endswithCIS "\cmd.exe"))

```