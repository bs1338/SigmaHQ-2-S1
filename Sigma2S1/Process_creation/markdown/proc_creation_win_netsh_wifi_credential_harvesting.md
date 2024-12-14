# proc_creation_win_netsh_wifi_credential_harvesting

## Title
Harvesting Of Wifi Credentials Via Netsh.EXE

## ID
42b1a5b8-353f-4f10-b256-39de4467faff

## Author
Andreas Hunkeler (@Karneades), oscd.community

## Date
2020-04-20

## Tags
attack.discovery, attack.credential-access, attack.t1040

## Description
Detect the harvesting of wifi credentials using netsh.exe

## References
https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "wlan" AND TgtProcCmdLine containsCIS " s" AND TgtProcCmdLine containsCIS " p" AND TgtProcCmdLine containsCIS " k" AND TgtProcCmdLine containsCIS "=clear") AND TgtProcImagePath endswithCIS "\netsh.exe"))

```