# proc_creation_win_squirrel_download

## Title
Arbitrary File Download Via Squirrel.EXE

## ID
1e75c1cc-c5d4-42aa-ac3d-91b0b68b3b4c

## Author
Nasreddine Bencherchali (Nextron Systems), Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community

## Date
2022-06-09

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects the usage of the "Squirrel.exe" to download arbitrary files. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)


## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Squirrel/
http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/
http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/

## False Positives
Expected FP with some Electron based applications such as (1Clipboard, Beaker Browser, Caret, Discord, GitHub Desktop, etc.)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " --download " OR TgtProcCmdLine containsCIS " --update " OR TgtProcCmdLine containsCIS " --updateRollback=") AND TgtProcCmdLine containsCIS "http" AND (TgtProcImagePath endswithCIS "\squirrel.exe" OR TgtProcImagePath endswithCIS "\update.exe")))

```