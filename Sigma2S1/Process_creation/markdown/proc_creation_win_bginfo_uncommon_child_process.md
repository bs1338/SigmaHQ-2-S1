# proc_creation_win_bginfo_uncommon_child_process

## Title
Uncommon Child Process Of BgInfo.EXE

## ID
aaf46cdc-934e-4284-b329-34aa701e3771

## Author
Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community

## Date
2019-10-26

## Tags
attack.execution, attack.t1059.005, attack.defense-evasion, attack.t1218, attack.t1202

## Description
Detects uncommon child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\bginfo.exe" OR SrcProcImagePath endswithCIS "\bginfo64.exe"))

```