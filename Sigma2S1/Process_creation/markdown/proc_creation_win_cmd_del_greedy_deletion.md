# proc_creation_win_cmd_del_greedy_deletion

## Title
Greedy File Deletion Using Del

## ID
204b17ae-4007-471b-917b-b917b315c5db

## Author
frack113 , X__Junior (Nextron Systems)

## Date
2021-12-02

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects execution of the "del" builtin command to remove files using greedy/wildcard expression. This is often used by malware to delete content of folders that perhaps contains the initial malware infection or to delete evidence.

## References
https://www.joesandbox.com/analysis/509330/0/html#1044F3BDBE3BB6F734E357235F4D5898582D
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/erase

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "del " OR TgtProcCmdLine containsCIS "erase ") AND (TgtProcCmdLine containsCIS "\\*.au3" OR TgtProcCmdLine containsCIS "\\*.dll" OR TgtProcCmdLine containsCIS "\\*.exe" OR TgtProcCmdLine containsCIS "\\*.js") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```