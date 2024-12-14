# proc_creation_win_imewbdld_download

## Title
Arbitrary File Download Via IMEWDBLD.EXE

## ID
863218bd-c7d0-4c52-80cd-0a96c09f54af

## Author
Swachchhanda Shrawan Poudel

## Date
2023-11-09

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects usage of "IMEWDBLD.exe" to download arbitrary files

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-10---windows---powershell-download
https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\IMEWDBLD.exe"))

```