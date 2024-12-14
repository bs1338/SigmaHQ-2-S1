# registry_set_hidden_extention

## Title
Registry Modification to Hidden File Extension

## ID
5df86130-4e95-4a54-90f7-26541b40aec2

## Author
frack113

## Date
2022-01-22

## Tags
attack.persistence, attack.t1137

## Description
Hides the file extension through modification of the registry

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-1---modify-registry-of-current-user-profile---cmd
https://unit42.paloaltonetworks.com/ransomware-families/
https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=TrojanSpy%3aMSIL%2fHakey.A

## False Positives
Administrative scripts

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "DWORD (0x00000002)" AND RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden") OR (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt")))

```