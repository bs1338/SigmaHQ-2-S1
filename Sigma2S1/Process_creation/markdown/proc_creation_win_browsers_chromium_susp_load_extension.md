# proc_creation_win_browsers_chromium_susp_load_extension

## Title
Suspicious Chromium Browser Instance Executed With Custom Extension

## ID
27ba3207-dd30-4812-abbf-5d20c57d474e

## Author
Aedan Russell, frack113, X__Junior (Nextron Systems)

## Date
2022-06-19

## Tags
attack.persistence, attack.t1176

## Description
Detects a suspicious process spawning a Chromium based browser process with the 'load-extension' flag to start an instance with a custom extension

## References
https://redcanary.com/blog/chromeloader/
https://emkc.org/s/RJjuLa
https://www.mandiant.com/resources/blog/lnk-between-browsers

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "--load-extension=" AND (TgtProcImagePath endswithCIS "\brave.exe" OR TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\opera.exe" OR TgtProcImagePath endswithCIS "\vivaldi.exe") AND (SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\wscript.exe")))

```