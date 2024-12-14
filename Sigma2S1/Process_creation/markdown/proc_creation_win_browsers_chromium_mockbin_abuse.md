# proc_creation_win_browsers_chromium_mockbin_abuse

## Title
Chromium Browser Headless Execution To Mockbin Like Site

## ID
1c526788-0abe-4713-862f-b520da5e5316

## Author
X__Junior (Nextron Systems)

## Date
2023-09-11

## Tags
attack.execution

## Description
Detects the execution of a Chromium based browser process with the "headless" flag and a URL pointing to the mockbin.org service (which can be used to exfiltrate data).

## References
https://www.zscaler.com/blogs/security-research/steal-it-campaign

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "--headless" AND (TgtProcImagePath endswithCIS "\brave.exe" OR TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\opera.exe" OR TgtProcImagePath endswithCIS "\vivaldi.exe") AND (TgtProcCmdLine containsCIS "://run.mocky" OR TgtProcCmdLine containsCIS "://mockbin")))

```