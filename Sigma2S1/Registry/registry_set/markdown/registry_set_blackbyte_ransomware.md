# registry_set_blackbyte_ransomware

## Title
Blackbyte Ransomware Registry

## ID
83314318-052a-4c90-a1ad-660ece38d276

## Author
frack113

## Date
2022-01-24

## Tags
attack.defense-evasion, attack.t1112

## Description
BlackByte set three different registry values to escalate privileges and begin setting the stage for lateral movement and encryption

## References
https://redcanary.com/blog/blackbyte-ransomware/?utm_source=twitter&utm_medium=social
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/blackbyte-ransomware-pt-1-in-depth-analysis/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath In Contains AnyCase ("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy","HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections","HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled"))))

```