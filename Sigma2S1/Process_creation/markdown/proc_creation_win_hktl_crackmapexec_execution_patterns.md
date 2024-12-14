# proc_creation_win_hktl_crackmapexec_execution_patterns

## Title
HackTool - CrackMapExec Execution Patterns

## ID
058f4380-962d-40a5-afce-50207d36d7e2

## Author
Thomas Patzke

## Date
2020-05-22

## Tags
attack.execution, attack.t1047, attack.t1053, attack.t1059.003, attack.t1059.001, attack.s0106

## Description
Detects various execution patterns of the CrackMapExec pentesting framework

## References
https://github.com/byt3bl33d3r/CrackMapExec

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine = "*cmd.exe /Q /c * 1> \\*\*\* 2>&1*" OR TgtProcCmdLine = "*cmd.exe /C * > \\*\*\* 2>&1*" OR TgtProcCmdLine = "*cmd.exe /C * > *\Temp\* 2>&1*" OR TgtProcCmdLine containsCIS "powershell.exe -exec bypass -noni -nop -w 1 -C \"" OR TgtProcCmdLine containsCIS "powershell.exe -noni -nop -w 1 -enc "))

```