# proc_creation_win_regsvr32_http_ip_pattern

## Title
Potentially Suspicious Regsvr32 HTTP IP Pattern

## ID
2dd2c217-bf68-437a-b57c-fe9fd01d5de8

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-11

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects regsvr32 execution to download and install DLLs located remotely where the address is an IP address.

## References
https://twitter.com/mrd0x/status/1461041276514623491
https://twitter.com/tccontre18/status/1480950986650832903
https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/

## False Positives
FQDNs that start with a number such as "7-Zip"

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\regsvr32.exe" AND (TgtProcCmdLine containsCIS " /i:http://1" OR TgtProcCmdLine containsCIS " /i:http://2" OR TgtProcCmdLine containsCIS " /i:http://3" OR TgtProcCmdLine containsCIS " /i:http://4" OR TgtProcCmdLine containsCIS " /i:http://5" OR TgtProcCmdLine containsCIS " /i:http://6" OR TgtProcCmdLine containsCIS " /i:http://7" OR TgtProcCmdLine containsCIS " /i:http://8" OR TgtProcCmdLine containsCIS " /i:http://9" OR TgtProcCmdLine containsCIS " /i:https://1" OR TgtProcCmdLine containsCIS " /i:https://2" OR TgtProcCmdLine containsCIS " /i:https://3" OR TgtProcCmdLine containsCIS " /i:https://4" OR TgtProcCmdLine containsCIS " /i:https://5" OR TgtProcCmdLine containsCIS " /i:https://6" OR TgtProcCmdLine containsCIS " /i:https://7" OR TgtProcCmdLine containsCIS " /i:https://8" OR TgtProcCmdLine containsCIS " /i:https://9" OR TgtProcCmdLine containsCIS " -i:http://1" OR TgtProcCmdLine containsCIS " -i:http://2" OR TgtProcCmdLine containsCIS " -i:http://3" OR TgtProcCmdLine containsCIS " -i:http://4" OR TgtProcCmdLine containsCIS " -i:http://5" OR TgtProcCmdLine containsCIS " -i:http://6" OR TgtProcCmdLine containsCIS " -i:http://7" OR TgtProcCmdLine containsCIS " -i:http://8" OR TgtProcCmdLine containsCIS " -i:http://9" OR TgtProcCmdLine containsCIS " -i:https://1" OR TgtProcCmdLine containsCIS " -i:https://2" OR TgtProcCmdLine containsCIS " -i:https://3" OR TgtProcCmdLine containsCIS " -i:https://4" OR TgtProcCmdLine containsCIS " -i:https://5" OR TgtProcCmdLine containsCIS " -i:https://6" OR TgtProcCmdLine containsCIS " -i:https://7" OR TgtProcCmdLine containsCIS " -i:https://8" OR TgtProcCmdLine containsCIS " -i:https://9")))

```