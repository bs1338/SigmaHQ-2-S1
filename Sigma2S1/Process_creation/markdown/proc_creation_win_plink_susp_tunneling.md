# proc_creation_win_plink_susp_tunneling

## Title
Potential RDP Tunneling Via Plink

## ID
f38ce0b9-5e97-4b47-a211-7dc8d8b871da

## Author
Florian Roth (Nextron Systems)

## Date
2022-08-04

## Tags
attack.command-and-control, attack.t1572

## Description
Execution of plink to perform data exfiltration and tunneling

## References
https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ":127.0.0.1:3389" AND TgtProcImagePath endswithCIS "\plink.exe") OR ((TgtProcCmdLine containsCIS ":3389" AND TgtProcImagePath endswithCIS "\plink.exe") AND (TgtProcCmdLine containsCIS " -P 443" OR TgtProcCmdLine containsCIS " -P 22"))))

```