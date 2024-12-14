# registry_set_disable_privacy_settings_experience

## Title
Disable Privacy Settings Experience in Registry

## ID
0372e1f9-0fd2-40f7-be1b-a7b2b848fa7b

## Author
frack113

## Date
2022-10-02

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects registry modifications that disable Privacy Settings Experience

## References
https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1562.001/T1562.001.md

## False Positives
Legitimate admin script

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath endswithCIS "\SOFTWARE\Policies\Microsoft\Windows\OOBE\DisablePrivacyExperience"))

```