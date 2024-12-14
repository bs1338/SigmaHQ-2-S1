# proc_creation_win_cmd_no_space_execution

## Title
Cmd.EXE Missing Space Characters Execution Anomaly

## ID
a16980c2-0c56-4de0-9a79-17971979efdd

## Author
Florian Roth (Nextron Systems)

## Date
2022-08-23

## Tags
attack.execution, attack.t1059.001

## Description
Detects Windows command lines that miss a space before or after the /c flag when running a command using the cmd.exe.
This could be a sign of obfuscation of a fat finger problem (typo by the developer).


## References
https://twitter.com/cyb3rops/status/1562072617552678912
https://ss64.com/nt/cmd.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "cmd.exe/c" OR TgtProcCmdLine containsCIS "\cmd/c" OR TgtProcCmdLine containsCIS "\"cmd/c" OR TgtProcCmdLine containsCIS "cmd.exe/k" OR TgtProcCmdLine containsCIS "\cmd/k" OR TgtProcCmdLine containsCIS "\"cmd/k" OR TgtProcCmdLine containsCIS "cmd.exe/r" OR TgtProcCmdLine containsCIS "\cmd/r" OR TgtProcCmdLine containsCIS "\"cmd/r") OR (TgtProcCmdLine containsCIS "/cwhoami" OR TgtProcCmdLine containsCIS "/cpowershell" OR TgtProcCmdLine containsCIS "/cschtasks" OR TgtProcCmdLine containsCIS "/cbitsadmin" OR TgtProcCmdLine containsCIS "/ccertutil" OR TgtProcCmdLine containsCIS "/kwhoami" OR TgtProcCmdLine containsCIS "/kpowershell" OR TgtProcCmdLine containsCIS "/kschtasks" OR TgtProcCmdLine containsCIS "/kbitsadmin" OR TgtProcCmdLine containsCIS "/kcertutil") OR (TgtProcCmdLine containsCIS "cmd.exe /c" OR TgtProcCmdLine containsCIS "cmd /c" OR TgtProcCmdLine containsCIS "cmd.exe /k" OR TgtProcCmdLine containsCIS "cmd /k" OR TgtProcCmdLine containsCIS "cmd.exe /r" OR TgtProcCmdLine containsCIS "cmd /r")) AND (NOT ((TgtProcCmdLine containsCIS "AppData\Local\Programs\Microsoft VS Code\resources\app\node_modules" OR TgtProcCmdLine endswithCIS "cmd.exe/c ." OR TgtProcCmdLine = "cmd.exe /c") OR (TgtProcCmdLine containsCIS "cmd.exe /c " OR TgtProcCmdLine containsCIS "cmd /c " OR TgtProcCmdLine containsCIS "cmd.exe /k " OR TgtProcCmdLine containsCIS "cmd /k " OR TgtProcCmdLine containsCIS "cmd.exe /r " OR TgtProcCmdLine containsCIS "cmd /r ")))))

```