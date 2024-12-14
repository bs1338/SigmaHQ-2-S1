# proc_creation_win_certutil_download_direct_ip

## Title
Suspicious File Downloaded From Direct IP Via Certutil.EXE

## ID
13e6fe51-d478-4c7e-b0f2-6da9b400a829

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of certutil with certain flags that allow the utility to download files from direct IPs.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
https://forensicitguy.github.io/agenttesla-vba-certutil-download/
https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
https://twitter.com/egre55/status/1087685529016193025
https://lolbas-project.github.io/lolbas/Binaries/Certutil/
https://twitter.com/_JohnHammond/status/1708910264261980634

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "urlcache " OR TgtProcCmdLine containsCIS "verifyctl ") AND (TgtProcCmdLine containsCIS "://1" OR TgtProcCmdLine containsCIS "://2" OR TgtProcCmdLine containsCIS "://3" OR TgtProcCmdLine containsCIS "://4" OR TgtProcCmdLine containsCIS "://5" OR TgtProcCmdLine containsCIS "://6" OR TgtProcCmdLine containsCIS "://7" OR TgtProcCmdLine containsCIS "://8" OR TgtProcCmdLine containsCIS "://9") AND TgtProcImagePath endswithCIS "\certutil.exe") AND (NOT TgtProcCmdLine containsCIS "://7-")))

```