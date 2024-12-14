# registry_set_disable_windows_firewall

## Title
Disable Windows Firewall by Registry

## ID
e78c408a-e2ea-43cd-b5ea-51975cf358c0

## Author
frack113

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1562.004

## Description
Detect set EnableFirewall to 0 to disable the Windows firewall

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1562.004/T1562.004.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\EnableFirewall" OR RegistryKeyPath endswithCIS "\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall")))

```