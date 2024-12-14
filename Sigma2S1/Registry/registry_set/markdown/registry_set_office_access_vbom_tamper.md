# registry_set_office_access_vbom_tamper

## Title
Trust Access Disable For VBApplications

## ID
1a5c46e9-f32f-42f7-b2bc-6e9084db7fbf

## Author
Trent Liffick (@tliffick), Nasreddine Bencherchali (Nextron Systems)

## Date
2020-05-22

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects registry changes to Microsoft Office "AccessVBOM" to a value of "1" which disables trust access for VBA on the victim machine and lets attackers execute malicious macros without any Microsoft Office warnings.

## References
https://twitter.com/inversecos/status/1494174785621819397
https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Security\AccessVBOM"))

```