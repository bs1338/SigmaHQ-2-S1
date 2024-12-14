# proc_creation_win_rdrleakdiag_process_dumping

## Title
Process Memory Dump via RdrLeakDiag.EXE

## ID
edadb1e5-5919-4e4c-8462-a9e643b02c4b

## Author
Cedric MAURUGEON, Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)

## Date
2021-09-24

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the use of the Microsoft Windows Resource Leak Diagnostic tool "rdrleakdiag.exe" to dump process memory

## References
https://www.pureid.io/dumping-abusing-windows-credentials-part-1/
https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
https://lolbas-project.github.io/lolbas/Binaries/Rdrleakdiag/
https://twitter.com/0gtweet/status/1299071304805560321?s=21
https://news.sophos.com/en-us/2024/06/05/operation-crimson-palace-a-technical-deep-dive

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-memdmp" OR TgtProcCmdLine containsCIS "/memdmp" OR TgtProcCmdLine containsCIS "â€“memdmp" OR TgtProcCmdLine containsCIS "â€”memdmp" OR TgtProcCmdLine containsCIS "â€•memdmp" OR TgtProcCmdLine containsCIS "fullmemdmp") AND (TgtProcCmdLine containsCIS " -o " OR TgtProcCmdLine containsCIS " /o " OR TgtProcCmdLine containsCIS " â€“o " OR TgtProcCmdLine containsCIS " â€”o " OR TgtProcCmdLine containsCIS " â€•o " OR TgtProcCmdLine containsCIS " -p " OR TgtProcCmdLine containsCIS " /p " OR TgtProcCmdLine containsCIS " â€“p " OR TgtProcCmdLine containsCIS " â€”p " OR TgtProcCmdLine containsCIS " â€•p ") AND TgtProcImagePath endswithCIS "\rdrleakdiag.exe"))

```