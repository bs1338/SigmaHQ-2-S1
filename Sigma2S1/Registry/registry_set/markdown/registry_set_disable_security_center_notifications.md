# registry_set_disable_security_center_notifications

## Title
Disable Windows Security Center Notifications

## ID
3ae1a046-f7db-439d-b7ce-b8b366b81fa6

## Author
frack113

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect set UseActionCenterExperience to 0 to disable the Windows security center notification

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath endswithCIS "Windows\CurrentVersion\ImmersiveShell\UseActionCenterExperience"))

```