# registry_set_change_security_zones

## Title
IE Change Domain Zone

## ID
45e112d0-7759-4c2a-aa36-9f8fb79d3393

## Author
frack113

## Date
2022-01-22

## Tags
attack.persistence, attack.t1137

## Description
Hides the file extension through modification of the registry

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-4---add-domain-to-trusted-sites-zone
https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries

## False Positives
Administrative scripts

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\" AND (NOT (RegistryValue In Contains AnyCase ("DWORD (0x00000000)","DWORD (0x00000001)","(Empty)")))))

```