# proc_creation_win_cdb_arbitrary_command_execution

## Title
Potential Binary Proxy Execution Via Cdb.EXE

## ID
b5c7395f-e501-4a08-94d4-57fe7a9da9d2

## Author
Beyu Denis, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-10-26

## Tags
attack.execution, attack.t1106, attack.defense-evasion, attack.t1218, attack.t1127

## Description
Detects usage of "cdb.exe" to launch arbitrary processes or commands from a debugger script file

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Cdb/
https://web.archive.org/web/20170715043507/http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
https://twitter.com/nas_bench/status/1534957360032120833

## False Positives
Legitimate use of debugging tools

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -c " OR TgtProcCmdLine containsCIS " -cf ") AND TgtProcImagePath endswithCIS "\cdb.exe"))

```