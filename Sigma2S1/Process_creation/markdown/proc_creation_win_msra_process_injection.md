# proc_creation_win_msra_process_injection

## Title
Potential Process Injection Via Msra.EXE

## ID
744a188b-0415-4792-896f-11ddb0588dbc

## Author
Alexander McDonald

## Date
2022-06-24

## Tags
attack.defense-evasion, attack.t1055

## Description
Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics

## References
https://www.microsoft.com/security/blog/2021/12/09/a-closer-look-at-qakbots-latest-building-blocks-and-how-to-knock-them-down/
https://www.fortinet.com/content/dam/fortinet/assets/analyst-reports/ar-qakbot.pdf

## False Positives
Legitimate use of Msra.exe

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\arp.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\netstat.exe" OR TgtProcImagePath endswithCIS "\nslookup.exe" OR TgtProcImagePath endswithCIS "\route.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\whoami.exe") AND SrcProcCmdLine endswithCIS "msra.exe" AND SrcProcImagePath endswithCIS "\msra.exe"))

```