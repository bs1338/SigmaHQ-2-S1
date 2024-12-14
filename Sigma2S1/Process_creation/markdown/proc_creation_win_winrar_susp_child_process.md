# proc_creation_win_winrar_susp_child_process

## Title
Potentially Suspicious Child Process Of WinRAR.EXE

## ID
146aace8-9bd6-42ba-be7a-0070d8027b76

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-31

## Tags
attack.execution, attack.t1203

## Description
Detects potentially suspicious child processes of WinRAR.exe.

## References
https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day/
https://github.com/knight0x07/WinRAR-Code-Execution-Vulnerability-CVE-2023-38831/blob/26ab6c40b6d2c09bb4fc60feaa4a3a90cfd20c23/Part-1-Overview.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\WinRAR.exe"))

```