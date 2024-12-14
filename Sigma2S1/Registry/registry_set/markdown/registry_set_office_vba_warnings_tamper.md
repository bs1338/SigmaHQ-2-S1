# registry_set_office_vba_warnings_tamper

## Title
Office Macros Warning Disabled

## ID
91239011-fe3c-4b54-9f24-15c86bb65913

## Author
Trent Liffick (@tliffick), Nasreddine Bencherchali (Nextron Systems)

## Date
2020-05-22

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects registry changes to Microsoft Office "VBAWarning" to a value of "1" which enables the execution of all macros, whether signed or unsigned.

## References
https://twitter.com/inversecos/status/1494174785621819397
https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Security\VBAWarnings"))

```