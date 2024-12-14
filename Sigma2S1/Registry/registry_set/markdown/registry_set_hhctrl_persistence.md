# registry_set_hhctrl_persistence

## Title
Persistence Via Hhctrl.ocx

## ID
f10ed525-97fe-4fed-be7c-2feecca941b1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker modifies the registry value of the "hhctrl" to point to a custom binary

## References
https://persistence-info.github.io/Data/hhctrl.html
https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32\(Default)" AND (NOT RegistryValue = "C:\Windows\System32\hhctrl.ocx")))

```