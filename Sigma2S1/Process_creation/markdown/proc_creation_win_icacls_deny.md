# proc_creation_win_icacls_deny

## Title
Use Icacls to Hide File to Everyone

## ID
4ae81040-fc1c-4249-bfa3-938d260214d9

## Author
frack113

## Date
2022-07-18

## Tags
attack.defense-evasion, attack.t1564.001

## Description
Detect use of icacls to deny access for everyone in Users folder sometimes used to hide malicious files

## References
https://app.any.run/tasks/1df999e6-1cb8-45e3-8b61-499d1b7d5a9b/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/deny" AND TgtProcCmdLine containsCIS "S-1-1-0:") AND TgtProcImagePath endswithCIS "\icacls.exe"))

```