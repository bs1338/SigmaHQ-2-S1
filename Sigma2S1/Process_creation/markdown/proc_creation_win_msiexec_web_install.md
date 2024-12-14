# proc_creation_win_msiexec_web_install

## Title
MsiExec Web Install

## ID
f7b5f842-a6af-4da5-9e95-e32478f3cd2f

## Author
Florian Roth (Nextron Systems)

## Date
2018-02-09

## Tags
attack.defense-evasion, attack.t1218.007, attack.command-and-control, attack.t1105

## Description
Detects suspicious msiexec process starts with web addresses as parameter

## References
https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " msiexec" AND TgtProcCmdLine containsCIS "://"))

```