# registry_set_persistence_outlook_todaypage

## Title
Potential Persistence Via Outlook Today Page

## ID
487bb375-12ef-41f6-baae-c6a1572b4dd1

## Author
Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand

## Date
2021-06-10

## Tags
attack.persistence, attack.t1112

## Description
Detects potential persistence activity via outlook today page.
An attacker can set a custom page to execute arbitrary code and link to it via the registry values "URL" and "UserDefinedUrl".


## References
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=74
https://trustedsec.com/blog/specula-turning-outlook-into-a-c2-with-one-registry-change

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "Software\Microsoft\Office\" AND RegistryKeyPath containsCIS "\Outlook\Today\") AND ((RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Stamp") OR (RegistryKeyPath endswithCIS "\URL" OR RegistryKeyPath endswithCIS "\UserDefinedUrl")) AND (NOT (SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\" OR SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Updates\")))))

```