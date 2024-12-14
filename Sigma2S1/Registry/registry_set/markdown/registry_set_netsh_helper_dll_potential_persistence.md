# registry_set_netsh_helper_dll_potential_persistence

## Title
Potential Persistence Via Netsh Helper DLL - Registry

## ID
c90362e0-2df3-4e61-94fe-b37615814cb1

## Author
Anish Bogati

## Date
2023-11-28

## Tags
attack.persistence, attack.t1546.007

## Description
Detects changes to the Netsh registry key to add a new DLL value. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper


## References
https://www.ired.team/offensive-security/persistence/t1128-netsh-helper-dll
https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/

## False Positives
Legitimate helper added by different programs and the OS

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue containsCIS ".dll" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\NetSh"))

```