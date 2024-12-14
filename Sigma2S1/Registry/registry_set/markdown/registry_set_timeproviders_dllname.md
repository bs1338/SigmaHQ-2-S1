# registry_set_timeproviders_dllname

## Title
New TimeProviders Registered With Uncommon DLL Name

## ID
e88a6ddc-74f7-463b-9b26-f69fc0d2ce85

## Author
frack113

## Date
2022-06-19

## Tags
attack.persistence, attack.privilege-escalation, attack.t1547.003

## Description
Detects processes setting a new DLL in DllName in under HKEY_LOCAL_MACHINE\ SYSTEM\CurrentControlSet\Services\W32Time\TimeProvider.
Adversaries may abuse time providers to execute DLLs when the system boots.
The Windows Time service (W32Time) enables time synchronization across and within domains.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.003/T1547.003.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Services\W32Time\TimeProviders" AND RegistryKeyPath endswithCIS "\DllName") AND (NOT (RegistryValue In Contains AnyCase ("%SystemRoot%\System32\vmictimeprovider.dll","%systemroot%\system32\w32time.dll","C:\Windows\SYSTEM32\w32time.DLL")))))

```