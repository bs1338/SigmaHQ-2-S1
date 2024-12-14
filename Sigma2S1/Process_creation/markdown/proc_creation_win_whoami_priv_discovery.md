# proc_creation_win_whoami_priv_discovery

## Title
Security Privileges Enumeration Via Whoami.EXE

## ID
97a80ec7-0e2f-4d05-9ef4-65760e634f6b

## Author
Florian Roth (Nextron Systems)

## Date
2021-05-05

## Tags
attack.privilege-escalation, attack.discovery, attack.t1033

## Description
Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privileges. This is often used after a privilege escalation attempt.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /priv" OR TgtProcCmdLine containsCIS " -priv") AND TgtProcImagePath endswithCIS "\whoami.exe"))

```