# proc_creation_win_sysinternals_psexesvc

## Title
PsExec Service Execution

## ID
fdfcbd78-48f1-4a4b-90ac-d82241e368c5

## Author
Thomas Patzke, Romaissa Adjailia, Florian Roth (Nextron Systems)

## Date
2017-06-12

## Tags
attack.execution

## Description
Detects launch of the PSEXESVC service, which means that this system was the target of a psexec remote execution

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
https://www.youtube.com/watch?v=ro2QuZTIMBM

## False Positives
Legitimate administrative tasks

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath = "C:\Windows\PSEXESVC.exe")

```