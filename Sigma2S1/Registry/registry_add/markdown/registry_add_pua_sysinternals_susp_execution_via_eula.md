# registry_add_pua_sysinternals_susp_execution_via_eula

## Title
PUA - Sysinternals Tools Execution - Registry

## ID
c7da8edc-49ae-45a2-9e61-9fd860e4e73d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-24

## Tags
attack.resource-development, attack.t1588.002

## Description
Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the "accepteula" registry key.

## References
https://twitter.com/Moti_B/status/1008587936735035392

## False Positives
Legitimate use of SysInternals tools. Filter the legitimate paths used in your environment

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "CreateKey" AND (RegistryKeyPath containsCIS "\Active Directory Explorer" OR RegistryKeyPath containsCIS "\Handle" OR RegistryKeyPath containsCIS "\LiveKd" OR RegistryKeyPath containsCIS "\Process Explorer" OR RegistryKeyPath containsCIS "\ProcDump" OR RegistryKeyPath containsCIS "\PsExec" OR RegistryKeyPath containsCIS "\PsLoglist" OR RegistryKeyPath containsCIS "\PsPasswd" OR RegistryKeyPath containsCIS "\SDelete" OR RegistryKeyPath containsCIS "\Sysinternals") AND RegistryKeyPath endswithCIS "\EulaAccepted"))

```