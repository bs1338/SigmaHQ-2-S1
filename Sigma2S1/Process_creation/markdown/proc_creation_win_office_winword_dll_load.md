# proc_creation_win_office_winword_dll_load

## Title
Potential Arbitrary DLL Load Using Winword

## ID
f7375e28-5c14-432f-b8d1-1db26c832df3

## Author
Victor Sergeev, oscd.community

## Date
2020-10-09

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects potential DLL sideloading using the Microsoft Office winword process via the '/l' flag.

## References
https://github.com/D4Vinci/One-Lin3r/blob/9fdfa5f0b9c698dfbd4cdfe7d2473192777ae1c6/one_lin3r/core/liners/windows/cmd/dll_loader_word.py

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/l " AND TgtProcCmdLine containsCIS ".dll") AND TgtProcImagePath endswithCIS "\WINWORD.exe"))

```