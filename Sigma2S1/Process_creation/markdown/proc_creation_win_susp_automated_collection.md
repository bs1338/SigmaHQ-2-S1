# proc_creation_win_susp_automated_collection

## Title
Automated Collection Command Prompt

## ID
f576a613-2392-4067-9d1a-9345fb58d8d1

## Author
frack113

## Date
2021-07-28

## Tags
attack.collection, attack.t1119, attack.credential-access, attack.t1552.001

## Description
Once established within a system or network, an adversary may use automated techniques for collecting internal data.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".doc" OR TgtProcCmdLine containsCIS ".docx" OR TgtProcCmdLine containsCIS ".xls" OR TgtProcCmdLine containsCIS ".xlsx" OR TgtProcCmdLine containsCIS ".ppt" OR TgtProcCmdLine containsCIS ".pptx" OR TgtProcCmdLine containsCIS ".rtf" OR TgtProcCmdLine containsCIS ".pdf" OR TgtProcCmdLine containsCIS ".txt") AND (TgtProcCmdLine containsCIS "dir " AND TgtProcCmdLine containsCIS " /b " AND TgtProcCmdLine containsCIS " /s ")))

```