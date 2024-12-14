# registry_set_allow_rdp_remote_assistance_feature

## Title
Allow RDP Remote Assistance Feature

## ID
37b437cf-3fc5-4c8e-9c94-1d7c9aff842b

## Author
frack113

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect enable rdp feature to allow specific user to rdp connect on the targeted machine

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

## False Positives
Legitimate use of the feature (alerts should be investigated either way)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "System\CurrentControlSet\Control\Terminal Server\fAllowToGetHelp"))

```