# proc_creation_win_squirrel_proxy_execution

## Title
Process Proxy Execution Via Squirrel.EXE

## ID
45239e6a-b035-4aaf-b339-8ad379fcb67e

## Author
Nasreddine Bencherchali (Nextron Systems), Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community

## Date
2022-06-09

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects the usage of the "Squirrel.exe" binary to execute arbitrary processes. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)


## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Squirrel/
http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/
http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/

## False Positives
Expected FP with some Electron based applications such as (1Clipboard, Beaker Browser, Caret, Discord, GitHub Desktop, etc.)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "--processStart" OR TgtProcCmdLine containsCIS "--processStartAndWait" OR TgtProcCmdLine containsCIS "--createShortcut") AND (TgtProcImagePath endswithCIS "\squirrel.exe" OR TgtProcImagePath endswithCIS "\update.exe")) AND (NOT ((TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\Discord\Update.exe" AND TgtProcCmdLine containsCIS " --processStart" AND TgtProcCmdLine containsCIS "Discord.exe") OR ((TgtProcCmdLine containsCIS "--createShortcut" OR TgtProcCmdLine containsCIS "--processStartAndWait") AND (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\GitHubDesktop\Update.exe" AND TgtProcCmdLine containsCIS "GitHubDesktop.exe")) OR ((TgtProcCmdLine containsCIS "--processStart" OR TgtProcCmdLine containsCIS "--createShortcut") AND (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\Microsoft\Teams\Update.exe" AND TgtProcCmdLine containsCIS "Teams.exe")) OR ((TgtProcCmdLine containsCIS "--processStart" OR TgtProcCmdLine containsCIS "--createShortcut") AND (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\yammerdesktop\Update.exe" AND TgtProcCmdLine containsCIS "Yammer.exe"))))))

```