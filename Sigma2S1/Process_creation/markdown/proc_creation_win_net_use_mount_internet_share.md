# proc_creation_win_net_use_mount_internet_share

## Title
Windows Internet Hosted WebDav Share Mount Via Net.EXE

## ID
7e6237fe-3ddb-438f-9381-9bf9de5af8d0

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-21

## Tags
attack.lateral-movement, attack.t1021.002

## Description
Detects when an internet hosted webdav share is mounted using the "net.exe" utility

## References
https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " use " AND TgtProcCmdLine containsCIS " http") AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```