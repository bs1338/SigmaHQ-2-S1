# registry_event_redmimicry_winnti_reg

## Title
RedMimicry Winnti Playbook Registry Manipulation

## ID
5b175490-b652-4b02-b1de-5b5b4083c5f8

## Author
Alexander Rausch

## Date
2020-06-24

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects actions caused by the RedMimicry Winnti playbook

## References
https://redmimicry.com

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "HKLM\SOFTWARE\Microsoft\HTMLHelp\data")

```