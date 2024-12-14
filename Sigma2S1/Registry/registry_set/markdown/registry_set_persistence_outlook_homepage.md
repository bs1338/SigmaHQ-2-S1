# registry_set_persistence_outlook_homepage

## Title
Potential Persistence Via Outlook Home Page

## ID
ddd171b5-2cc6-4975-9e78-f0eccd08cc76

## Author
Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand

## Date
2021-06-09

## Tags
attack.persistence, attack.t1112

## Description
Detects potential persistence activity via outlook home page.
An attacker can set a home page to achieve code execution and persistence by editing the WebView registry keys.


## References
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=70
https://support.microsoft.com/en-us/topic/outlook-home-page-feature-is-missing-in-folder-properties-d207edb7-aa02-46c5-b608-5d9dbed9bd04?ui=en-us&rs=en-us&ad=us
https://trustedsec.com/blog/specula-turning-outlook-into-a-c2-with-one-registry-change

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Software\Microsoft\Office\" AND RegistryKeyPath containsCIS "\Outlook\WebView\") AND RegistryKeyPath endswithCIS "\URL"))

```