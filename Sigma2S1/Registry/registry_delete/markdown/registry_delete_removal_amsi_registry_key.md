# registry_delete_removal_amsi_registry_key

## Title
Removal Of AMSI Provider Registry Keys

## ID
41d1058a-aea7-4952-9293-29eaaf516465

## Author
frack113

## Date
2021-06-07

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the deletion of AMSI provider registry key entries in HKLM\Software\Microsoft\AMSI. This technique could be used by an attacker in order to disable AMSI inspection.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
https://seclists.org/fulldisclosure/2020/Mar/45

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "DeleteKey" AND (RegistryKeyPath endswithCIS "{2781761E-28E0-4109-99FE-B9D127C57AFE}" OR RegistryKeyPath endswithCIS "{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}")))

```