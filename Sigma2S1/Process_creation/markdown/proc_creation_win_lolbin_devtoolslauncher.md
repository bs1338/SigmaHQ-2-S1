# proc_creation_win_lolbin_devtoolslauncher

## Title
Devtoolslauncher.exe Executes Specified Binary

## ID
cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6

## Author
Beyu Denis, oscd.community (rule), @_felamos (idea)

## Date
2019-10-12

## Tags
attack.defense-evasion, attack.t1218

## Description
The Devtoolslauncher.exe executes other binary

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devtoolslauncher/
https://twitter.com/_felamos/status/1179811992841797632

## False Positives
Legitimate use of devtoolslauncher.exe by legitimate user

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "LaunchForDeploy" AND TgtProcImagePath endswithCIS "\devtoolslauncher.exe"))

```