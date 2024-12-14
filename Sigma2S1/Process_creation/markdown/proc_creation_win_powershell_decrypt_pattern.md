# proc_creation_win_powershell_decrypt_pattern

## Title
PowerShell Execution With Potential Decryption Capabilities

## ID
434c08ba-8406-4d15-8b24-782cb071a691

## Author
X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-30

## Tags
attack.execution

## Description
Detects PowerShell commands that decrypt an ".LNK" "file to drop the next stage of the malware.

## References
https://research.checkpoint.com/2023/chinese-threat-actors-targeting-europe-in-smugx-campaign/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Get-ChildItem " OR TgtProcCmdLine containsCIS "dir " OR TgtProcCmdLine containsCIS "gci " OR TgtProcCmdLine containsCIS "ls ") AND (TgtProcCmdLine containsCIS "Get-Content " OR TgtProcCmdLine containsCIS "gc " OR TgtProcCmdLine containsCIS "cat " OR TgtProcCmdLine containsCIS "type " OR TgtProcCmdLine containsCIS "ReadAllBytes") AND ((TgtProcCmdLine containsCIS " ^| " AND TgtProcCmdLine containsCIS "\*.lnk" AND TgtProcCmdLine containsCIS "-Recurse" AND TgtProcCmdLine containsCIS "-Skip ") OR (TgtProcCmdLine containsCIS " -ExpandProperty " AND TgtProcCmdLine containsCIS "\*.lnk" AND TgtProcCmdLine containsCIS "WriteAllBytes" AND TgtProcCmdLine containsCIS " .length "))))

```