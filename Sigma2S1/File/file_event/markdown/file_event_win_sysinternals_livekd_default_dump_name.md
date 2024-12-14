# file_event_win_sysinternals_livekd_default_dump_name

## Title
LiveKD Kernel Memory Dump File Created

## ID
814ddeca-3d31-4265-8e07-8cc54fb44903

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-16

## Tags
attack.defense-evasion, attack.privilege-escalation

## Description
Detects the creation of a file that has the same name as the default LiveKD kernel memory dump.

## References
Internal Research

## False Positives
In rare occasions administrators might leverage LiveKD to perform live kernel debugging. This should not be allowed on production systems. Investigate and apply additional filters where necessary.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath = "C:\Windows\livekd.dmp")

```