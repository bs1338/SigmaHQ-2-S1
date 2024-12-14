# proc_creation_win_wsl_child_processes_anomalies

## Title
WSL Child Process Anomaly

## ID
2267fe65-0681-42ad-9a6d-46553d3f3480

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-23

## Tags
attack.execution, attack.defense-evasion, attack.t1218, attack.t1202

## Description
Detects uncommon or suspicious child processes spawning from a WSL process. This could indicate an attempt to evade parent/child relationship detections or persistence attempts via cron using WSL

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/
https://twitter.com/nas_bench/status/1535431474429808642

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\wsl.exe" OR SrcProcImagePath endswithCIS "\wslhost.exe") AND ((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcImagePath containsCIS "\AppData\Local\Temp\" OR TgtProcImagePath containsCIS "C:\Users\Public\" OR TgtProcImagePath containsCIS "C:\Windows\Temp\" OR TgtProcImagePath containsCIS "C:\Temp\" OR TgtProcImagePath containsCIS "\Downloads\" OR TgtProcImagePath containsCIS "\Desktop\"))))

```