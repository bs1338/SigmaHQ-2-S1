# registry_set_persistence_typed_paths

## Title
Potential Persistence Via TypedPaths

## ID
086ae989-9ca6-4fe7-895a-759c5544f247

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-22

## Tags
attack.persistence

## Description
Detects modification addition to the 'TypedPaths' key in the user or admin registry from a non standard application. Which might indicate persistence attempt

## References
https://twitter.com/dez_/status/1560101453150257154
https://forensafe.com/blogs/typedpaths.html

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\" AND (NOT (SrcProcImagePath In Contains AnyCase ("C:\Windows\explorer.exe","C:\Windows\SysWOW64\explorer.exe")))))

```