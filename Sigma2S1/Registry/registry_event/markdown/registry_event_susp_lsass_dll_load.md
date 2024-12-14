# registry_event_susp_lsass_dll_load

## Title
DLL Load via LSASS

## ID
b3503044-60ce-4bf4-bbcb-e3db98788823

## Author
Florian Roth (Nextron Systems)

## Date
2019-10-16

## Tags
attack.execution, attack.persistence, attack.t1547.008

## Description
Detects a method to load DLL via LSASS process using an undocumented Registry key

## References
https://blog.xpnsec.com/exploring-mimikatz-part-1/
https://twitter.com/SBousseaden/status/1183745981189427200

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt" OR RegistryKeyPath containsCIS "\CurrentControlSet\Services\NTDS\LsaDbExtPt") AND (NOT ((RegistryValue In Contains AnyCase ("%%systemroot%%\system32\ntdsa.dll","%%systemroot%%\system32\lsadb.dll")) AND SrcProcImagePath = "C:\Windows\system32\lsass.exe"))))

```