# registry_set_netsh_help_dll_persistence_susp_location

## Title
New Netsh Helper DLL Registered From A Suspicious Location

## ID
e7b18879-676e-4a0e-ae18-27039185a8e7

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-11-28

## Tags
attack.persistence, attack.t1546.007

## Description
Detects changes to the Netsh registry key to add a new DLL value that is located on a suspicious location. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper


## References
https://www.ired.team/offensive-security/persistence/t1128-netsh-helper-dll
https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\NetSh" AND ((RegistryValue containsCIS ":\Perflogs\" OR RegistryValue containsCIS ":\Users\Public\" OR RegistryValue containsCIS ":\Windows\Temp\" OR RegistryValue containsCIS "\AppData\Local\Temp\" OR RegistryValue containsCIS "\Temporary Internet") OR ((RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Favorites\") OR (RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Favourites\") OR (RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Contacts\") OR (RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Pictures\")))))

```