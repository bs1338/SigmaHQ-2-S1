# proc_creation_win_browsers_chromium_headless_file_download

## Title
File Download with Headless Browser

## ID
0e8cfe08-02c9-4815-a2f8-0d157b7ed33e

## Author
Sreeman, Florian Roth (Nextron Systems)

## Date
2022-01-04

## Tags
attack.command-and-control, attack.t1105

## Description
Detects execution of chromium based browser in headless mode using the "dump-dom" command line to download files

## References
https://twitter.com/mrd0x/status/1478234484881436672?s=12
https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "--headless" AND TgtProcCmdLine containsCIS "dump-dom" AND TgtProcCmdLine containsCIS "http") AND (TgtProcImagePath endswithCIS "\brave.exe" OR TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\opera.exe" OR TgtProcImagePath endswithCIS "\vivaldi.exe")))

```