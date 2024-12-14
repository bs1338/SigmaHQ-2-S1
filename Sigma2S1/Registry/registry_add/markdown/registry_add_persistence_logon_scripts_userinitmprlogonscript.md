# registry_add_persistence_logon_scripts_userinitmprlogonscript

## Title
Potential Persistence Via Logon Scripts - Registry

## ID
9ace0707-b560-49b8-b6ca-5148b42f39fb

## Author
Tom Ueltschi (@c_APT_ure)

## Date
2019-01-12

## Tags
attack.t1037.001, attack.persistence, attack.lateral-movement

## Description
Detects creation of "UserInitMprLogonScript" registry value which can be used as a persistence method by malicious actors

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1037.001/T1037.001.md

## False Positives
Investigate the contents of the "UserInitMprLogonScript" value to determine of the added script is legitimate

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "CreateKey" AND RegistryKeyPath containsCIS "UserInitMprLogonScript"))

```