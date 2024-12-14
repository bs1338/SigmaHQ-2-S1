# registry_set_asep_reg_keys_modification_wow6432node_currentversion

## Title
Wow6432Node Windows NT CurrentVersion Autorun Keys Modification

## ID
480421f9-417f-4d3b-9552-fd2728443ec8

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
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion" AND (RegistryKeyPath containsCIS "\Windows\Appinit_Dlls" OR RegistryKeyPath containsCIS "\Image File Execution Options" OR RegistryKeyPath containsCIS "\Drivers32") AND (NOT (RegistryValue In Contains AnyCase ("(Empty)","\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")))))

```