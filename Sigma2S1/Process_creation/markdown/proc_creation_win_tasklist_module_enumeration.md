# proc_creation_win_tasklist_module_enumeration

## Title
Loaded Module Enumeration Via Tasklist.EXE

## ID
34275eb8-fa19-436b-b959-3d9ecd53fa1f

## Author
Swachchhanda Shrawan Poudel

## Date
2024-02-12

## Tags
attack.t1003

## Description
Detects the enumeration of a specific DLL or EXE being used by a binary via "tasklist.exe".
This is often used by attackers in order to find the specific process identifier (PID) that is using the DLL in question.
In order to dump the process memory or perform other nefarious actions.


## References
https://www.n00py.io/2021/05/dumping-plaintext-rdp-credentials-from-svchost-exe/
https://pentestlab.blog/tag/svchost/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-m" OR TgtProcCmdLine containsCIS "/m" OR TgtProcCmdLine containsCIS "â€“m" OR TgtProcCmdLine containsCIS "â€”m" OR TgtProcCmdLine containsCIS "â€•m") AND TgtProcImagePath endswithCIS "\tasklist.exe" AND TgtProcCmdLine containsCIS "rdpcorets.dll"))

```