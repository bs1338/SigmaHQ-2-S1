# proc_creation_win_pua_nircmd

## Title
PUA - NirCmd Execution

## ID
4e2ed651-1906-4a59-a78a-18220fca1b22

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-24

## Tags
attack.execution, attack.t1569.002, attack.s0029

## Description
Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity

## References
https://www.nirsoft.net/utils/nircmd.html
https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
https://www.nirsoft.net/utils/nircmd2.html#using

## False Positives
Legitimate use by administrators

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " execmd " OR TgtProcCmdLine containsCIS ".exe script " OR TgtProcCmdLine containsCIS ".exe shexec " OR TgtProcCmdLine containsCIS " runinteractive ") OR TgtProcImagePath endswithCIS "\NirCmd.exe") OR ((TgtProcCmdLine containsCIS " exec " OR TgtProcCmdLine containsCIS " exec2 ") AND (TgtProcCmdLine containsCIS " show " OR TgtProcCmdLine containsCIS " hide "))))

```