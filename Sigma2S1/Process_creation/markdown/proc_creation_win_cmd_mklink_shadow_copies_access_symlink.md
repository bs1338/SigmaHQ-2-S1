# proc_creation_win_cmd_mklink_shadow_copies_access_symlink

## Title
VolumeShadowCopy Symlink Creation Via Mklink

## ID
40b19fa6-d835-400c-b301-41f3a2baacaf

## Author
Teymur Kheirkhabarov, oscd.community

## Date
2019-10-22

## Tags
attack.credential-access, attack.t1003.002, attack.t1003.003

## Description
Shadow Copies storage symbolic link creation using operating systems utilities

## References
https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

## False Positives
Legitimate administrator working with shadow copies, access for backup purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "mklink" AND TgtProcCmdLine containsCIS "HarddiskVolumeShadowCopy"))

```