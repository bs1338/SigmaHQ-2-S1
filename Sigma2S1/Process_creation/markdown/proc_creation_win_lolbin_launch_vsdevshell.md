# proc_creation_win_lolbin_launch_vsdevshell

## Title
Launch-VsDevShell.PS1 Proxy Execution

## ID
45d3a03d-f441-458c-8883-df101a3bb146

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1216.001

## Description
Detects the use of the 'Launch-VsDevShell.ps1' Microsoft signed script to execute commands.

## References
https://twitter.com/nas_bench/status/1535981653239255040

## False Positives
Legitimate usage of the script by a developer

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "VsWherePath " OR TgtProcCmdLine containsCIS "VsInstallationPath ") AND TgtProcCmdLine containsCIS "Launch-VsDevShell.ps1"))

```