# proc_creation_win_powershell_get_clipboard

## Title
PowerShell Get-Clipboard Cmdlet Via CLI

## ID
b9aeac14-2ffd-4ad3-b967-1354a4e628c3

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2020-05-02

## Tags
attack.collection, attack.t1115

## Description
Detects usage of the 'Get-Clipboard' cmdlet via CLI

## References
https://github.com/OTRF/detection-hackathon-apt29/issues/16
https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "Get-Clipboard")

```