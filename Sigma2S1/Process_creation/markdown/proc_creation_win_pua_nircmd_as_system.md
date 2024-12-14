# proc_creation_win_pua_nircmd_as_system

## Title
PUA - NirCmd Execution As LOCAL SYSTEM

## ID
d9047477-0359-48c9-b8c7-792cedcdc9c4

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-24

## Tags
attack.execution, attack.t1569.002, attack.s0029

## Description
Detects the use of NirCmd tool for command execution as SYSTEM user

## References
https://www.nirsoft.net/utils/nircmd.html
https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
https://www.nirsoft.net/utils/nircmd2.html#using

## False Positives
Legitimate use by administrators

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS " runassystem ")

```