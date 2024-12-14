# proc_creation_win_pua_nsudo

## Title
PUA - NSudo Execution

## ID
771d1eb5-9587-4568-95fb-9ec44153a012

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali

## Date
2022-01-24

## Tags
attack.execution, attack.t1569.002, attack.s0029

## Description
Detects the use of NSudo tool for command execution

## References
https://web.archive.org/web/20221019044836/https://nsudo.m2team.org/en-us/
https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/

## False Positives
Legitimate use by administrators

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-U:S " OR TgtProcCmdLine containsCIS "-U:T " OR TgtProcCmdLine containsCIS "-U:E " OR TgtProcCmdLine containsCIS "-P:E " OR TgtProcCmdLine containsCIS "-M:S " OR TgtProcCmdLine containsCIS "-M:H " OR TgtProcCmdLine containsCIS "-U=S " OR TgtProcCmdLine containsCIS "-U=T " OR TgtProcCmdLine containsCIS "-U=E " OR TgtProcCmdLine containsCIS "-P=E " OR TgtProcCmdLine containsCIS "-M=S " OR TgtProcCmdLine containsCIS "-M=H " OR TgtProcCmdLine containsCIS "-ShowWindowMode:Hide") AND (TgtProcImagePath endswithCIS "\NSudo.exe" OR TgtProcImagePath endswithCIS "\NSudoLC.exe" OR TgtProcImagePath endswithCIS "\NSudoLG.exe")))

```