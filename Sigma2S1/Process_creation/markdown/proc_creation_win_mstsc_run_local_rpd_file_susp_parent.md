# proc_creation_win_mstsc_run_local_rpd_file_susp_parent

## Title
Mstsc.EXE Execution From Uncommon Parent

## ID
ff3b6b39-e765-42f9-bb2c-ea6761e0e0f6

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-18

## Tags
attack.lateral-movement

## Description
Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.

## References
https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\mstsc.exe" AND (SrcProcImagePath endswithCIS "\brave.exe" OR SrcProcImagePath endswithCIS "\CCleanerBrowser.exe" OR SrcProcImagePath endswithCIS "\chrome.exe" OR SrcProcImagePath endswithCIS "\chromium.exe" OR SrcProcImagePath endswithCIS "\firefox.exe" OR SrcProcImagePath endswithCIS "\iexplore.exe" OR SrcProcImagePath endswithCIS "\microsoftedge.exe" OR SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\opera.exe" OR SrcProcImagePath endswithCIS "\vivaldi.exe" OR SrcProcImagePath endswithCIS "\whale.exe" OR SrcProcImagePath endswithCIS "\outlook.exe")))

```