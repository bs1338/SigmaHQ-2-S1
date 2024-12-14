# registry_set_disabled_pua_protection_on_microsoft_defender

## Title
Disable PUA Protection on Windows Defender

## ID
8ffc5407-52e3-478f-9596-0a7371eafe13

## Author
Austin Songer @austinsonger

## Date
2021-08-04

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects disabling Windows Defender PUA protection

## References
https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Policies\Microsoft\Windows Defender\PUAProtection"))

```