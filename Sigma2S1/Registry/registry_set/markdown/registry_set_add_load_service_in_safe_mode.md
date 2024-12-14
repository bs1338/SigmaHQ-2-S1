# registry_set_add_load_service_in_safe_mode

## Title
Registry Persistence via Service in Safe Mode

## ID
1547e27c-3974-43e2-a7d7-7f484fb928ec

## Author
frack113

## Date
2022-04-04

## Tags
attack.defense-evasion, attack.t1564.001

## Description
Detects the modification of the registry to allow a driver or service to persist in Safe Mode.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-33---windows-add-registry-value-to-load-service-in-safe-mode-without-network
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-34---windows-add-registry-value-to-load-service-in-safe-mode-with-network

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "Service" AND (RegistryKeyPath containsCIS "\Control\SafeBoot\Minimal\" OR RegistryKeyPath containsCIS "\Control\SafeBoot\Network\") AND RegistryKeyPath endswithCIS "\(Default)") AND (NOT (SrcProcImagePath = "C:\WINDOWS\system32\msiexec.exe" AND (RegistryKeyPath endswithCIS "\Control\SafeBoot\Minimal\SAVService\(Default)" OR RegistryKeyPath endswithCIS "\Control\SafeBoot\Network\SAVService\(Default)")))))

```