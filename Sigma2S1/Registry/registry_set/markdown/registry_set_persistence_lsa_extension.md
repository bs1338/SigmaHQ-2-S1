# registry_set_persistence_lsa_extension

## Title
Potential Persistence Via LSA Extensions

## ID
41f6531d-af6e-4c6e-918f-b946f2b85a36

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker modifies the "REG_MULTI_SZ" value named "Extensions" to include a custom DLL to achieve persistence via lsass.
The "Extensions" list contains filenames of DLLs being automatically loaded by lsass.exe. Each DLL has its InitializeLsaExtension() method called after loading.


## References
https://persistence-info.github.io/Data/lsaaextension.html
https://twitter.com/0gtweet/status/1476286368385019906

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv\Extensions")

```