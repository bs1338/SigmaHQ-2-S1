# registry_set_servicedll_hijack

## Title
ServiceDll Hijack

## ID
612e47e9-8a59-43a6-b404-f48683f45bd6

## Author
frack113

## Date
2022-02-04

## Tags
attack.persistence, attack.privilege-escalation, attack.t1543.003

## Description
Detects changes to the "ServiceDLL" value related to a service in the registry.
This is often used as a method of persistence.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md#atomic-test-4---tinyturla-backdoor-service-w64time
https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/

## False Positives
Administrative scripts
Installation of a service

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryKeyPath containsCIS "\System\" AND RegistryKeyPath containsCIS "ControlSet" AND RegistryKeyPath containsCIS "\Services\") AND RegistryKeyPath endswithCIS "\Parameters\ServiceDll") AND (NOT ((RegistryValue = "%%systemroot%%\system32\ntdsa.dll" AND SrcProcImagePath = "C:\Windows\system32\lsass.exe" AND RegistryKeyPath endswithCIS "\Services\NTDS\Parameters\ServiceDll") OR SrcProcImagePath = "C:\Windows\System32\poqexec.exe" OR RegistryValue = "C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll")) AND (NOT (RegistryValue = "C:\Windows\System32\STAgent.dll" AND SrcProcImagePath endswithCIS "\regsvr32.exe"))))

```