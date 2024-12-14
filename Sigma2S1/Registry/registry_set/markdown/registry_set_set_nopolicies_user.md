# registry_set_set_nopolicies_user

## Title
Registry Explorer Policy Modification

## ID
1c3121ed-041b-4d97-a075-07f54f20fb4a

## Author
frack113

## Date
2022-03-18

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects registry modifications that disable internal tools or functions in explorer (malware like Agent Tesla uses this technique)

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md

## False Positives
Legitimate admin script

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoLogOff" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDesktop" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFind" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoControlPanel" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFileMenu" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoClose" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoSetTaskbar" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPropertiesMyDocuments" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoTrayContextMenu")))

```