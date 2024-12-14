# proc_creation_win_hh_chm_remote_download_or_execution

## Title
Remote CHM File Download/Execution Via HH.EXE

## ID
f57c58b3-ee69-4ef5-9041-455bf39aaa89

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-29

## Tags
attack.defense-evasion, attack.t1218.001

## Description
Detects the usage of "hh.exe" to execute/download remotely hosted ".chm" files.

## References
https://www.splunk.com/en_us/blog/security/follina-for-protocol-handlers.html
https://github.com/redcanaryco/atomic-red-team/blob/1cf4dd51f83dcb0ebe6ade902d6157ad2dbc6ac8/atomics/T1218.001/T1218.001.md
https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://" OR TgtProcCmdLine containsCIS "\\") AND TgtProcImagePath endswithCIS "\hh.exe"))

```