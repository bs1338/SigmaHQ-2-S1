# registry_set_asep_reg_keys_modification_winsock2

## Title
WinSock2 Autorun Keys Modification

## ID
d6c2ce7e-afb5-4337-9ca4-4b5254ed0565

## Author
Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)

## Date
2019-10-25

## Tags
attack.persistence, attack.t1547.001

## Description
Detects modification of autostart extensibility point (ASEP) in registry.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
Legitimate administrator sets up autorun keys for legitimate reason

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\System\CurrentControlSet\Services\WinSock2\Parameters" AND (RegistryKeyPath containsCIS "\Protocol_Catalog9\Catalog_Entries" OR RegistryKeyPath containsCIS "\NameSpace_Catalog5\Catalog_Entries") AND (NOT (RegistryValue = "(Empty)" OR SrcProcImagePath = "C:\Windows\System32\MsiExec.exe" OR SrcProcImagePath = "C:\Windows\syswow64\MsiExec.exe"))))

```