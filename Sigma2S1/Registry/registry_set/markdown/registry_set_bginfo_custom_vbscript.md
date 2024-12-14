# registry_set_bginfo_custom_vbscript

## Title
New BgInfo.EXE Custom VBScript Registry Configuration

## ID
992dd79f-dde8-4bb0-9085-6350ba97cfb3

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-16

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom VBScript via "BgInfo.exe"

## References
Internal Research

## False Positives
Legitimate VBScript

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue startswithCIS "4" AND EventType = "SetValue" AND RegistryKeyPath containsCIS "\Software\Winternals\BGInfo\UserFields\"))

```