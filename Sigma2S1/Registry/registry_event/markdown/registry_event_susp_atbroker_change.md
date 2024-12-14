# registry_event_susp_atbroker_change

## Title
Atbroker Registry Change

## ID
9577edbb-851f-4243-8c91-1d5b50c1a39b

## Author
Mateusz Wydra, oscd.community

## Date
2020-10-13

## Tags
attack.defense-evasion, attack.t1218, attack.persistence, attack.t1547

## Description
Detects creation/modification of Assistive Technology applications and persistence with usage of 'at'

## References
http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
https://lolbas-project.github.io/lolbas/Binaries/Atbroker/

## False Positives
Creation of non-default, legitimate at usage

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs" OR RegistryKeyPath containsCIS "Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration") AND (NOT ((RegistryValue = "(Empty)" AND SrcProcImagePath = "C:\Windows\system32\atbroker.exe" AND RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration") OR (SrcProcImagePath startswithCIS "C:\Windows\Installer\MSI" AND RegistryKeyPath containsCIS "Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs")))))

```