# proc_creation_win_infdefaultinstall_execute_sct_scripts

## Title
InfDefaultInstall.exe .inf Execution

## ID
ce7cf472-6fcc-490a-9481-3786840b5d9b

## Author
frack113

## Date
2021-07-13

## Tags
attack.defense-evasion, attack.t1218

## Description
Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md#atomic-test-4---infdefaultinstallexe-inf-execution
https://lolbas-project.github.io/lolbas/Binaries/Infdefaultinstall/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "InfDefaultInstall.exe " AND TgtProcCmdLine containsCIS ".inf"))

```