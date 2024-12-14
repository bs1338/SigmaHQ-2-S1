# registry_set_turn_on_dev_features

## Title
Potential Signing Bypass Via Windows Developer Features - Registry

## ID
b110ebaf-697f-4da1-afd5-b536fa27a2c1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-12

## Tags
attack.defense-evasion

## Description
Detects when the enablement of developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.

## References
https://twitter.com/malmoeb/status/1560536653709598721
https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\AppModelUnlock" OR RegistryKeyPath containsCIS "\Policies\Microsoft\Windows\Appx\") AND (RegistryKeyPath endswithCIS "\AllowAllTrustedApps" OR RegistryKeyPath endswithCIS "\AllowDevelopmentWithoutDevLicense")))

```