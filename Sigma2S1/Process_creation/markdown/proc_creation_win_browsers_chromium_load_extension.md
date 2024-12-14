# proc_creation_win_browsers_chromium_load_extension

## Title
Chromium Browser Instance Executed With Custom Extension

## ID
88d6e60c-759d-4ac1-a447-c0f1466c2d21

## Author
Aedan Russell, frack113, X__Junior (Nextron Systems)

## Date
2022-06-19

## Tags
attack.persistence, attack.t1176

## Description
Detects a Chromium based browser process with the 'load-extension' flag to start a instance with a custom extension

## References
https://redcanary.com/blog/chromeloader/
https://emkc.org/s/RJjuLa
https://www.mandiant.com/resources/blog/lnk-between-browsers

## False Positives
Usage of Chrome Extensions in testing tools such as BurpSuite will trigger this alert

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "--load-extension=" AND (TgtProcImagePath endswithCIS "\brave.exe" OR TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\opera.exe" OR TgtProcImagePath endswithCIS "\vivaldi.exe")))

```