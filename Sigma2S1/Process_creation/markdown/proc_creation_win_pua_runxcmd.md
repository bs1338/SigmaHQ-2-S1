# proc_creation_win_pua_runxcmd

## Title
PUA - RunXCmd Execution

## ID
93199800-b52a-4dec-b762-75212c196542

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-24

## Tags
attack.execution, attack.t1569.002, attack.s0029

## Description
Detects the use of the RunXCmd tool to execute commands with System or TrustedInstaller accounts

## References
https://www.d7xtech.com/free-software/runx/
https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/

## False Positives
Legitimate use by administrators

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /account=system " OR TgtProcCmdLine containsCIS " /account=ti ") AND TgtProcCmdLine containsCIS "/exec="))

```