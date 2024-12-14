# proc_creation_win_net_use_mount_admin_share

## Title
Windows Admin Share Mount Via Net.EXE

## ID
3abd6094-7027-475f-9630-8ab9be7b9725

## Author
oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, wagga

## Date
2020-10-05

## Tags
attack.lateral-movement, attack.t1021.002

## Description
Detects when an admin share is mounted using net.exe

## References
https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view

## False Positives
Administrators

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " use " AND TgtProcCmdLine = "* \\*\*$*") AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```