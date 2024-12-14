# registry_add_persistence_amsi_providers

## Title
Potential Persistence Via New AMSI Providers - Registry

## ID
33efc23c-6ea2-4503-8cfe-bdf82ce8f705

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker registers a new AMSI provider in order to achieve persistence

## References
https://persistence-info.github.io/Data/amsi.html
https://github.com/gtworek/PSBits/blob/8d767892f3b17eefa4d0668f5d2df78e844f01d8/FakeAMSI/FakeAMSI.c

## False Positives
Legitimate security products adding their own AMSI providers. Filter these according to your environment

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "CreateKey" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\AMSI\Providers\" OR RegistryKeyPath containsCIS "\SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers\")) AND (NOT (SrcProcImagePath startswithCIS "C:\Windows\System32\" OR SrcProcImagePath startswithCIS "C:\Program Files\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\"))))

```