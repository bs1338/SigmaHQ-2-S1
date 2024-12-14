# proc_creation_win_susp_electron_app_children

## Title
Suspicious Electron Application Child Processes

## ID
f26eb764-fd89-464b-85e2-dc4a8e6e77b8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-21

## Tags
attack.execution

## Description
Detects suspicious child processes of electron apps (teams, discord, slack, etc.). This could be a potential sign of ".asar" file tampering (See reference section for more information) or binary execution proxy through specific CLI arguments (see related rule)


## References
https://taggart-tech.com/quasar-electron/
https://github.com/mttaggart/quasar
https://positive.security/blog/ms-officecmd-rce
https://lolbas-project.github.io/lolbas/Binaries/Msedge/
https://lolbas-project.github.io/lolbas/Binaries/Teams/
https://lolbas-project.github.io/lolbas/Binaries/msedgewebview2/
https://medium.com/@MalFuzzer/one-electron-to-rule-them-all-dc2e9b263daf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\chrome.exe" OR SrcProcImagePath endswithCIS "\discord.exe" OR SrcProcImagePath endswithCIS "\GitHubDesktop.exe" OR SrcProcImagePath endswithCIS "\keybase.exe" OR SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\msedgewebview2.exe" OR SrcProcImagePath endswithCIS "\msteams.exe" OR SrcProcImagePath endswithCIS "\slack.exe" OR SrcProcImagePath endswithCIS "\teams.exe") AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\whoami.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcImagePath containsCIS ":\ProgramData\" OR TgtProcImagePath containsCIS ":\Temp\" OR TgtProcImagePath containsCIS "\AppData\Local\Temp\" OR TgtProcImagePath containsCIS "\Users\Public\" OR TgtProcImagePath containsCIS "\Windows\Temp\")) AND (NOT (TgtProcCmdLine containsCIS "\NVSMI\nvidia-smi.exe" AND TgtProcImagePath endswithCIS "\cmd.exe" AND SrcProcImagePath endswithCIS "\Discord.exe"))))

```