# proc_creation_win_net_use_mount_share

## Title
Windows Share Mount Via Net.EXE

## ID
f117933c-980c-4f78-b384-e3d838111165

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-02

## Tags
attack.lateral-movement, attack.t1021.002

## Description
Detects when a share is mounted using the "net.exe" utility

## References
https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view

## False Positives
Legitimate activity by administrators and scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " use " OR TgtProcCmdLine containsCIS " \\") AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```