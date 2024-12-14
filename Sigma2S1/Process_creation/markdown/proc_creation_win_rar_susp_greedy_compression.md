# proc_creation_win_rar_susp_greedy_compression

## Title
Suspicious Greedy Compression Using Rar.EXE

## ID
afe52666-401e-4a02-b4ff-5d128990b8cb

## Author
X__Junior (Nextron Systems), Florian Roth (Nextron Systems)

## Date
2022-12-15

## Tags
attack.execution, attack.t1059

## Description
Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes

## References
https://decoded.avast.io/martinchlumecky/png-steganography

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\rar.exe" OR TgtProcDisplayName = "Command line RAR") OR (TgtProcCmdLine containsCIS ".exe a " OR TgtProcCmdLine containsCIS " a -m")) AND ((TgtProcCmdLine containsCIS " -hp" AND TgtProcCmdLine containsCIS " -r ") AND (TgtProcCmdLine = "* *:\\*.*" OR TgtProcCmdLine = "* *:\\\*.*" OR TgtProcCmdLine = "* *:\$Recycle.bin\*" OR TgtProcCmdLine = "* *:\PerfLogs\*" OR TgtProcCmdLine = "* *:\Temp*" OR TgtProcCmdLine = "* *:\Users\Public\*" OR TgtProcCmdLine = "* *:\Windows\*" OR TgtProcCmdLine containsCIS " %public%"))))

```