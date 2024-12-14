# proc_creation_win_lolbin_openwith

## Title
OpenWith.exe Executes Specified Binary

## ID
cec8e918-30f7-4e2d-9bfa-a59cc97ae60f

## Author
Beyu Denis, oscd.community (rule), @harr0ey (idea)

## Date
2019-10-12

## Tags
attack.defense-evasion, attack.t1218

## Description
The OpenWith.exe executes other binary

## References
https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OSBinaries/Openwith.yml
https://twitter.com/harr0ey/status/991670870384021504

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/c" AND TgtProcImagePath endswithCIS "\OpenWith.exe"))

```