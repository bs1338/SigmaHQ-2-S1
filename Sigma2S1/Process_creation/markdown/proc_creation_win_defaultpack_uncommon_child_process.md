# proc_creation_win_defaultpack_uncommon_child_process

## Title
Uncommon Child Process Of Defaultpack.EXE

## ID
b2309017-4235-44fe-b5af-b15363011957

## Author
frack113

## Date
2022-12-31

## Tags
attack.t1218, attack.defense-evasion, attack.execution

## Description
Detects uncommon child processes of "DefaultPack.EXE" binary as a proxy to launch other programs

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/DefaultPack/
https://www.echotrail.io/insights/search/defaultpack.exe

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\DefaultPack.exe")

```