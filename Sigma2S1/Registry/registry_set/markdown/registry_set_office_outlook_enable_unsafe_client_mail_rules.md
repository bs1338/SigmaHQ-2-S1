# registry_set_office_outlook_enable_unsafe_client_mail_rules

## Title
Outlook EnableUnsafeClientMailRules Setting Enabled - Registry

## ID
6763c6c8-bd01-4687-bc8d-4fa52cf8ba08

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-08

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects an attacker trying to enable the outlook security setting "EnableUnsafeClientMailRules" which allows outlook to run applications or execute macros

## References
https://support.microsoft.com/en-us/topic/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro-in-outlook-2016-and-outlook-2013-e4964b72-173c-959d-5d7b-ead562979048
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=44

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Outlook\Security\EnableUnsafeClientMailRules"))

```