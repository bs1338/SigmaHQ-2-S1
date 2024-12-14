# proc_creation_win_iis_susp_module_registration

## Title
Suspicious IIS Module Registration

## ID
043c4b8b-3a54-4780-9682-081cb6b8185c

## Author
Florian Roth (Nextron Systems), Microsoft (idea)

## Date
2022-08-04

## Tags
attack.persistence, attack.t1505.004

## Description
Detects a suspicious IIS module registration as described in Microsoft threat report on IIS backdoors

## References
https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\w3wp.exe" AND (TgtProcCmdLine containsCIS "appcmd.exe add module" OR (TgtProcCmdLine containsCIS " system.enterpriseservices.internal.publish" AND TgtProcImagePath endswithCIS "\powershell.exe") OR (TgtProcCmdLine containsCIS "gacutil" AND TgtProcCmdLine containsCIS " /I"))))

```