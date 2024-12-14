# registry_set_office_outlook_security_settings

## Title
Outlook Security Settings Updated - Registry

## ID
c3cefdf4-6703-4e1c-bad8-bf422fc5015a

## Author
frack113

## Date
2021-12-28

## Tags
attack.persistence, attack.t1137

## Description
Detects changes to the registry values related to outlook security settings

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1137/T1137.md
https://learn.microsoft.com/en-us/outlook/troubleshoot/security/information-about-email-security-settings

## False Positives
Administrative activity

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Office\" AND RegistryKeyPath containsCIS "\Outlook\Security\"))

```