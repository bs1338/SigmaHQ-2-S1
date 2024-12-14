# registry_event_esentutl_volume_shadow_copy_service_keys

## Title
Esentutl Volume Shadow Copy Service Keys

## ID
5aad0995-46ab-41bd-a9ff-724f41114971

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-10-20

## Tags
attack.credential-access, attack.t1003.002

## Description
Detects the volume shadow copy service initialization and processing via esentutl. Registry keys such as HKLM\\System\\CurrentControlSet\\Services\\VSS\\Diag\\VolSnap\\Volume are captured.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "esentutl.exe" AND RegistryKeyPath containsCIS "System\CurrentControlSet\Services\VSS") AND (NOT RegistryKeyPath containsCIS "System\CurrentControlSet\Services\VSS\Start")))

```