# proc_creation_win_msxsl_remote_execution

## Title
Remote XSL Execution Via Msxsl.EXE

## ID
75d0a94e-6252-448d-a7be-d953dff527bb

## Author
Swachchhanda Shrawan Poudel

## Date
2023-11-09

## Tags
attack.defense-evasion, attack.t1220

## Description
Detects the execution of the "msxsl" binary with an "http" keyword in the command line. This might indicate a potential remote execution of XSL files.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1220/T1220.md
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msxsl/

## False Positives
Msxsl is not installed by default and is deprecated, so unlikely on most systems.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "http" AND TgtProcImagePath endswithCIS "\msxsl.exe"))

```