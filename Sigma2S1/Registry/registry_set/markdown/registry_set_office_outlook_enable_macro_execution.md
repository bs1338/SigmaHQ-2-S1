# registry_set_office_outlook_enable_macro_execution

## Title
Outlook Macro Execution Without Warning Setting Enabled

## ID
e3b50fa5-3c3f-444e-937b-0a99d33731cd

## Author
@ScoubiMtl

## Date
2021-04-05

## Tags
attack.persistence, attack.command-and-control, attack.t1137, attack.t1008, attack.t1546

## Description
Detects the modification of Outlook security setting to allow unprompted execution of macros.

## References
https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue containsCIS "0x00000001" AND RegistryKeyPath endswithCIS "\Outlook\Security\Level"))

```