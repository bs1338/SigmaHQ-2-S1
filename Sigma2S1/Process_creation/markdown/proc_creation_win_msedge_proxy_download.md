# proc_creation_win_msedge_proxy_download

## Title
Arbitrary File Download Via MSEDGE_PROXY.EXE

## ID
e84d89c4-f544-41ca-a6af-4b92fd38b023

## Author
Swachchhanda Shrawan Poudel

## Date
2023-11-09

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects usage of "msedge_proxy.exe" to download arbitrary files

## References
https://lolbas-project.github.io/lolbas/Binaries/msedge_proxy/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\msedge_proxy.exe"))

```