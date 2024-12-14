# registry_set_asep_reg_keys_modification_system_scripts

## Title
System Scripts Autorun Keys Modification

## ID
e7a2fd40-3ae1-4a85-bf80-15cf624fb1b1

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
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Software\Policies\Microsoft\Windows\System\Scripts" AND (RegistryKeyPath containsCIS "\Startup" OR RegistryKeyPath containsCIS "\Shutdown" OR RegistryKeyPath containsCIS "\Logon" OR RegistryKeyPath containsCIS "\Logoff") AND (NOT RegistryValue = "(Empty)")))

```