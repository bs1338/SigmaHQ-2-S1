# proc_creation_win_rundll32_parent_explorer

## Title
Rundll32 Spawned Via Explorer.EXE

## ID
1723e720-616d-4ddc-ab02-f7e3685a4713

## Author
CD_ROM_

## Date
2022-05-21

## Tags
attack.defense-evasion

## Description
Detects execution of "rundll32.exe" with a parent process of Explorer.exe. This has been observed by variants of Raspberry Robin, as first reported by Red Canary.

## References
https://redcanary.com/blog/raspberry-robin/
https://thedfirreport.com/2022/09/26/bumblebee-round-two/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\rundll32.exe" AND SrcProcImagePath endswithCIS "\explorer.exe") AND (NOT (TgtProcCmdLine containsCIS " C:\Windows\System32\" OR TgtProcCmdLine endswithCIS " -localserver 22d8c27b-47a1-48d1-ad08-7da7abd79617"))))

```