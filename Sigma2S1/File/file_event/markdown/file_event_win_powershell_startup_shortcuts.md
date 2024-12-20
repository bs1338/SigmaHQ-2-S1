# file_event_win_powershell_startup_shortcuts

## Title
Potential Startup Shortcut Persistence Via PowerShell.EXE

## ID
92fa78e7-4d39-45f1-91a3-8b23f3f1088d

## Author
Christopher Peacock '@securepeacock', SCYTHE

## Date
2021-10-24

## Tags
attack.persistence, attack.t1547.001

## Description
Detects PowerShell writing startup shortcuts.
This procedure was highlighted in Red Canary Intel Insights Oct. 2021, "We frequently observe adversaries using PowerShell to write malicious .lnk files into the startup directory to establish persistence.
Accordingly, this detection opportunity is likely to identify persistence mechanisms in multiple threats.
In the context of Yellow Cockatoo, this persistence mechanism eventually launches the command-line script that leads to the installation of a malicious DLL"


## References
https://redcanary.com/blog/intelligence-insights-october-2021/
https://github.com/redcanaryco/atomic-red-team/blob/36d49de4c8b00bf36054294b4a1fcbab3917d7c5/atomics/T1547.001/T1547.001.md#atomic-test-7---add-executable-shortcut-link-to-user-startup-folder

## False Positives
Depending on your environment accepted applications may leverage this at times. It is recommended to search for anomalies inidicative of malware.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe") AND TgtFilePath containsCIS "\start menu\programs\startup\" AND TgtFilePath endswithCIS ".lnk"))

```