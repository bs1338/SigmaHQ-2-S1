# proc_creation_win_susp_electron_execution_proxy

## Title
Potentially Suspicious Electron Application CommandLine

## ID
378a05d8-963c-46c9-bcce-13c7657eac99

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-05

## Tags
attack.execution

## Description
Detects potentially suspicious CommandLine of electron apps (teams, discord, slack, etc.). This could be a sign of abuse to proxy execution through a signed binary.

## References
https://positive.security/blog/ms-officecmd-rce
https://lolbas-project.github.io/lolbas/Binaries/Teams/
https://lolbas-project.github.io/lolbas/Binaries/Msedge/
https://lolbas-project.github.io/lolbas/Binaries/msedgewebview2/
https://medium.com/@MalFuzzer/one-electron-to-rule-them-all-dc2e9b263daf
https://chromium.googlesource.com/chromium/chromium/+/master/content/public/common/content_switches.cc

## False Positives
Legitimate usage for debugging purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "--browser-subprocess-path" OR TgtProcCmdLine containsCIS "--gpu-launcher" OR TgtProcCmdLine containsCIS "--renderer-cmd-prefix" OR TgtProcCmdLine containsCIS "--utility-cmd-prefix") AND (TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\code.exe" OR TgtProcImagePath endswithCIS "\discord.exe" OR TgtProcImagePath endswithCIS "\GitHubDesktop.exe" OR TgtProcImagePath endswithCIS "\keybase.exe" OR TgtProcImagePath endswithCIS "\msedge_proxy.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\msedgewebview2.exe" OR TgtProcImagePath endswithCIS "\msteams.exe" OR TgtProcImagePath endswithCIS "\slack.exe" OR TgtProcImagePath endswithCIS "\Teams.exe")))

```