# registry_set_hide_file

## Title
Displaying Hidden Files Feature Disabled

## ID
5a5152f1-463f-436b-b2f5-8eceb3964b42

## Author
frack113

## Date
2022-04-02

## Tags
attack.defense-evasion, attack.t1564.001

## Description
Detects modifications to the "Hidden" and "ShowSuperHidden" explorer registry values in order to disable showing of hidden files and system files.
 This technique is abused by several malware families to hide their files from normal users.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md#atomic-test-8---hide-files-through-registry

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowSuperHidden" OR RegistryKeyPath endswithCIS "\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden")))

```