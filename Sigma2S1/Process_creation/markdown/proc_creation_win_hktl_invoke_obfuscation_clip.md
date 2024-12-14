# proc_creation_win_hktl_invoke_obfuscation_clip

## Title
Invoke-Obfuscation CLIP+ Launcher

## ID
b222df08-0e07-11eb-adc1-0242ac120002

## Author
Jonathan Cheong, oscd.community

## Date
2020-10-13

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated use of Clip.exe to execute PowerShell

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/c" OR TgtProcCmdLine containsCIS "/r") AND (TgtProcCmdLine containsCIS "cmd" AND TgtProcCmdLine containsCIS "&&" AND TgtProcCmdLine containsCIS "clipboard]::" AND TgtProcCmdLine containsCIS "-f")))

```