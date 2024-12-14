# proc_creation_win_hktl_certify

## Title
HackTool - Certify Execution

## ID
762f2482-ff21-4970-8939-0aa317a886bb

## Author
pH-T (Nextron Systems)

## Date
2023-04-17

## Tags
attack.discovery, attack.credential-access, attack.t1649

## Description
Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.

## References
https://github.com/GhostPack/Certify

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\Certify.exe" OR TgtProcDisplayName containsCIS "Certify") OR ((TgtProcCmdLine containsCIS ".exe cas " OR TgtProcCmdLine containsCIS ".exe find " OR TgtProcCmdLine containsCIS ".exe pkiobjects " OR TgtProcCmdLine containsCIS ".exe request " OR TgtProcCmdLine containsCIS ".exe download ") AND (TgtProcCmdLine containsCIS " /vulnerable" OR TgtProcCmdLine containsCIS " /template:" OR TgtProcCmdLine containsCIS " /altname:" OR TgtProcCmdLine containsCIS " /domain:" OR TgtProcCmdLine containsCIS " /path:" OR TgtProcCmdLine containsCIS " /ca:"))))

```