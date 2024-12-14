# registry_set_sentinelone_shell_context_tampering

## Title
Potential SentinelOne Shell Context Menu Scan Command Tampering

## ID
6c304b02-06e6-402d-8be4-d5833cdf8198

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-03-06

## Tags
attack.persistence

## Description
Detects potentially suspicious changes to the SentinelOne context menu scan command by a process other than SentinelOne.

## References
https://mrd0x.com/sentinelone-persistence-via-menu-context/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\shell\SentinelOneScan\command\" AND (NOT ((SrcProcImagePath endswithCIS "C:\Program Files\SentinelOne\" OR SrcProcImagePath endswithCIS "C:\Program Files (x86)\SentinelOne\") OR (RegistryValue containsCIS "\SentinelScanFromContextMenu.exe" AND (RegistryValue startswithCIS "C:\Program Files\SentinelOne\Sentinel Agent" OR RegistryValue startswithCIS "C:\Program Files (x86)\SentinelOne\Sentinel Agent"))))))

```