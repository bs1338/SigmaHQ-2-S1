# registry_set_persistence_chm

## Title
Potential Persistence Via CHM Helper DLL

## ID
976dd1f2-a484-45ec-aa1d-0e87e882262b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker modifies the registry key "HtmlHelp Author" to achieve persistence

## References
https://persistence-info.github.io/Data/htmlhelpauthor.html
https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Software\Microsoft\HtmlHelp Author\Location" OR RegistryKeyPath containsCIS "\Software\WOW6432Node\Microsoft\HtmlHelp Author\Location"))

```