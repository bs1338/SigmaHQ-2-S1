# proc_creation_win_browsers_chromium_headless_exec

## Title
Browser Execution In Headless Mode

## ID
ef9dcfed-690c-4c5d-a9d1-482cd422225c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-12

## Tags
attack.command-and-control, attack.t1105

## Description
Detects execution of Chromium based browser in headless mode

## References
https://twitter.com/mrd0x/status/1478234484881436672?s=12
https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "--headless" AND (TgtProcImagePath endswithCIS "\brave.exe" OR TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\opera.exe" OR TgtProcImagePath endswithCIS "\vivaldi.exe")))

```