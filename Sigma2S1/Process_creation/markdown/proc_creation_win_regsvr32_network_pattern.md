# proc_creation_win_regsvr32_network_pattern

## Title
Potentially Suspicious Regsvr32 HTTP/FTP Pattern

## ID
867356ee-9352-41c9-a8f2-1be690d78216

## Author
Florian Roth (Nextron Systems)

## Date
2023-05-24

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects regsvr32 execution to download/install/register new DLLs that are hosted on Web or FTP servers.

## References
https://twitter.com/mrd0x/status/1461041276514623491
https://twitter.com/tccontre18/status/1480950986650832903
https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /i" OR TgtProcCmdLine containsCIS " -i") AND TgtProcImagePath endswithCIS "\regsvr32.exe" AND (TgtProcCmdLine containsCIS "ftp" OR TgtProcCmdLine containsCIS "http")))

```