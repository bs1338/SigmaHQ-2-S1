# registry_set_persistence_natural_language

## Title
Potential Persistence Via DLLPathOverride

## ID
a1b1fd53-9c4a-444c-bae0-34a330fc7aa8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker adds a new "DLLPathOverride" value to the "Natural Language" key in order to achieve persistence which will get invoked by "SearchIndexer.exe" process

## References
https://persistence-info.github.io/Data/naturallanguage6.html
https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SYSTEM\CurrentControlSet\Control\ContentIndex\Language\" AND (RegistryKeyPath containsCIS "\StemmerDLLPathOverride" OR RegistryKeyPath containsCIS "\WBDLLPathOverride" OR RegistryKeyPath containsCIS "\StemmerClass" OR RegistryKeyPath containsCIS "\WBreakerClass")))

```