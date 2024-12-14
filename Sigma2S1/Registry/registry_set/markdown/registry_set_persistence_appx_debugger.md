# registry_set_persistence_appx_debugger

## Title
Potential Persistence Using DebugPath

## ID
df4dc653-1029-47ba-8231-3c44238cc0ae

## Author
frack113

## Date
2022-07-27

## Tags
attack.persistence, attack.t1546.015

## Description
Detects potential persistence using Appx DebugPath

## References
https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/
https://github.com/rootm0s/WinPwnage

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "Classes\ActivatableClasses\Package\Microsoft." AND RegistryKeyPath endswithCIS "\DebugPath") OR (RegistryKeyPath containsCIS "\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\Microsoft." AND RegistryKeyPath endswithCIS "\(Default)")))

```