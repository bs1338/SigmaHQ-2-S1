# proc_creation_win_setres_uncommon_child_process

## Title
Uncommon Child Process Of Setres.EXE

## ID
835e75bf-4bfd-47a4-b8a6-b766cac8bcb7

## Author
@gott_cyber, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-11

## Tags
attack.defense-evasion, attack.t1218, attack.t1202

## Description
Detects uncommon child process of Setres.EXE.
Setres.EXE is a Windows server only process and tool that can be used to set the screen resolution.
It can potentially be abused in order to launch any arbitrary file with a name containing the word "choice" from the current execution path.


## References
https://lolbas-project.github.io/lolbas/Binaries/Setres/
https://twitter.com/0gtweet/status/1583356502340870144
https://strontic.github.io/xcyclopedia/library/setres.exe-0E30E4C09637D7A128A37B59A3BC4D09.html
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "\choice" AND SrcProcImagePath endswithCIS "\setres.exe") AND (NOT (TgtProcImagePath endswithCIS "C:\Windows\System32\choice.exe" OR TgtProcImagePath endswithCIS "C:\Windows\SysWOW64\choice.exe"))))

```