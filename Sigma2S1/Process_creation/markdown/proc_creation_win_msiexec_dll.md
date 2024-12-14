# proc_creation_win_msiexec_dll

## Title
DllUnregisterServer Function Call Via Msiexec.EXE

## ID
84f52741-8834-4a8c-a413-2eb2269aa6c8

## Author
frack113

## Date
2022-04-24

## Tags
attack.defense-evasion, attack.t1218.007

## Description
Detects MsiExec loading a DLL and calling its DllUnregisterServer function

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
https://lolbas-project.github.io/lolbas/Binaries/Msiexec/
https://twitter.com/_st0pp3r_/status/1583914515996897281

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ".dll" AND (TgtProcCmdLine containsCIS " -z " OR TgtProcCmdLine containsCIS " /z " OR TgtProcCmdLine containsCIS " â€“z " OR TgtProcCmdLine containsCIS " â€”z " OR TgtProcCmdLine containsCIS " â€•z ") AND TgtProcImagePath endswithCIS "\msiexec.exe"))

```