# proc_creation_win_lodctr_performance_counter_tampering

## Title
Rebuild Performance Counter Values Via Lodctr.EXE

## ID
cc9d3712-6310-4320-b2df-7cb408274d53

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-15

## Tags
attack.execution

## Description
Detects the execution of "lodctr.exe" to rebuild the performance counter registry values. This can be abused by attackers by providing a malicious config file to overwrite performance counter configuration to confuse and evade monitoring and security solutions.

## References
https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr

## False Positives
Legitimate usage by an administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -r" OR TgtProcCmdLine containsCIS " /r" OR TgtProcCmdLine containsCIS " â€“r" OR TgtProcCmdLine containsCIS " â€”r" OR TgtProcCmdLine containsCIS " â€•r"))

```