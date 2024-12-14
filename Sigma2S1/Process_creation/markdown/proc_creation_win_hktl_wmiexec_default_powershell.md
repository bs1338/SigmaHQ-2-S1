# proc_creation_win_hktl_wmiexec_default_powershell

## Title
HackTool - Wmiexec Default Powershell Command

## ID
022eaba8-f0bf-4dd9-9217-4604b0bb3bb0

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-08

## Tags
attack.defense-evasion, attack.lateral-movement

## Description
Detects the execution of PowerShell with a specific flag sequence that is used by the Wmiexec script

## References
https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/examples/wmiexec.py

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc")

```