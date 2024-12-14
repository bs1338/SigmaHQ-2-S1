# proc_creation_win_certutil_download

## Title
Suspicious Download Via Certutil.EXE

## ID
19b08b1c-861d-4e75-a1ef-ea0c1baf202b

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of certutil with certain flags that allow the utility to download files.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
https://forensicitguy.github.io/agenttesla-vba-certutil-download/
https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
https://twitter.com/egre55/status/1087685529016193025
https://lolbas-project.github.io/lolbas/Binaries/Certutil/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "urlcache " OR TgtProcCmdLine containsCIS "verifyctl ") AND TgtProcCmdLine containsCIS "http" AND TgtProcImagePath endswithCIS "\certutil.exe"))

```