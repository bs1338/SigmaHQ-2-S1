# proc_creation_win_hktl_certipy

## Title
HackTool - Certipy Execution

## ID
6938366d-8954-4ddc-baff-c830b3ba8fcd

## Author
pH-T (Nextron Systems), Sittikorn Sangrattanapitak

## Date
2023-04-17

## Tags
attack.discovery, attack.credential-access, attack.t1649

## Description
Detects Certipy execution, a tool for Active Directory Certificate Services enumeration and abuse based on PE metadata characteristics and common command line arguments.


## References
https://github.com/ly4k/Certipy
https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\Certipy.exe" OR TgtProcDisplayName containsCIS "Certipy") OR ((TgtProcCmdLine containsCIS " account " OR TgtProcCmdLine containsCIS " auth " OR TgtProcCmdLine containsCIS " cert " OR TgtProcCmdLine containsCIS " find " OR TgtProcCmdLine containsCIS " forge " OR TgtProcCmdLine containsCIS " ptt " OR TgtProcCmdLine containsCIS " relay " OR TgtProcCmdLine containsCIS " req " OR TgtProcCmdLine containsCIS " shadow " OR TgtProcCmdLine containsCIS " template ") AND (TgtProcCmdLine containsCIS " -bloodhound" OR TgtProcCmdLine containsCIS " -ca-pfx " OR TgtProcCmdLine containsCIS " -dc-ip " OR TgtProcCmdLine containsCIS " -kirbi" OR TgtProcCmdLine containsCIS " -old-bloodhound" OR TgtProcCmdLine containsCIS " -pfx " OR TgtProcCmdLine containsCIS " -target" OR TgtProcCmdLine containsCIS " -template" OR TgtProcCmdLine containsCIS " -username " OR TgtProcCmdLine containsCIS " -vulnerable" OR TgtProcCmdLine containsCIS "auth -pfx" OR TgtProcCmdLine containsCIS "shadow auto" OR TgtProcCmdLine containsCIS "shadow list"))))

```