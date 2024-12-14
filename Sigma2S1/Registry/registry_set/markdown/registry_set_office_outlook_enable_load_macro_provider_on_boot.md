# registry_set_office_outlook_enable_load_macro_provider_on_boot

## Title
Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting

## ID
396ae3eb-4174-4b9b-880e-dc0364d78a19

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2021-04-05

## Tags
attack.persistence, attack.command-and-control, attack.t1137, attack.t1008, attack.t1546

## Description
Detects the modification of Outlook setting "LoadMacroProviderOnBoot" which if enabled allows the automatic loading of any configured VBA project/module

## References
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53
https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue containsCIS "0x00000001" AND RegistryKeyPath endswithCIS "\Outlook\LoadMacroProviderOnBoot"))

```