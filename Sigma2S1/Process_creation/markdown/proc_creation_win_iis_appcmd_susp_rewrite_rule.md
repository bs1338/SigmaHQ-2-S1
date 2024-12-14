# proc_creation_win_iis_appcmd_susp_rewrite_rule

## Title
Suspicious IIS URL GlobalRules Rewrite Via AppCmd

## ID
7c8af9b2-dcae-41a2-a9db-b28c288b5f08

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-22

## Tags
attack.defense-evasion

## Description
Detects usage of "appcmd" to create new global URL rewrite rules. This behaviour has been observed being used by threat actors to add new rules so they can access their webshells.

## References
https://twitter.com/malmoeb/status/1616702107242971144
https://learn.microsoft.com/en-us/answers/questions/739120/how-to-add-re-write-global-rule-with-action-type-r

## False Positives
Legitimate usage of appcmd to add new URL rewrite rules

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "set" AND TgtProcCmdLine containsCIS "config" AND TgtProcCmdLine containsCIS "section:system.webServer/rewrite/globalRules" AND TgtProcCmdLine containsCIS "commit:") AND TgtProcImagePath endswithCIS "\appcmd.exe"))

```