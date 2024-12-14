# registry_add_pua_sysinternals_execution_via_eula

## Title
PUA - Sysinternal Tool Execution - Registry

## ID
25ffa65d-76d8-4da5-a832-3f2b0136e133

## Author
Markus Neis

## Date
2017-08-28

## Tags
attack.resource-development, attack.t1588.002

## Description
Detects the execution of a Sysinternals Tool via the creation of the "accepteula" registry key

## References
https://twitter.com/Moti_B/status/1008587936735035392

## False Positives
Legitimate use of SysInternals tools
Programs that use the same Registry Key

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "CreateKey" AND RegistryKeyPath endswithCIS "\EulaAccepted"))

```