# proc_creation_win_bginfo_suspicious_child_process

## Title
Suspicious Child Process Of BgInfo.EXE

## ID
811f459f-9231-45d4-959a-0266c6311987

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-16

## Tags
attack.execution, attack.t1059.005, attack.defense-evasion, attack.t1218, attack.t1202

## Description
Detects suspicious child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\notepad.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcImagePath containsCIS "\AppData\Local\" OR TgtProcImagePath containsCIS "\AppData\Roaming\" OR TgtProcImagePath containsCIS ":\Users\Public\" OR TgtProcImagePath containsCIS ":\Temp\" OR TgtProcImagePath containsCIS ":\Windows\Temp\" OR TgtProcImagePath containsCIS ":\PerfLogs\")) AND (SrcProcImagePath endswithCIS "\bginfo.exe" OR SrcProcImagePath endswithCIS "\bginfo64.exe")))

```