# registry_set_persistence_shim_database_susp_application

## Title
Suspicious Shim Database Patching Activity

## ID
bf344fea-d947-4ef4-9192-34d008315d3a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-01

## Tags
attack.persistence, attack.t1546.011

## Description
Detects installation of new shim databases that try to patch sections of known processes for potential process injection or persistence.

## References
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/pillowmint-fin7s-monkey-thief/
https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\" AND (RegistryKeyPath endswithCIS "\csrss.exe" OR RegistryKeyPath endswithCIS "\dllhost.exe" OR RegistryKeyPath endswithCIS "\explorer.exe" OR RegistryKeyPath endswithCIS "\RuntimeBroker.exe" OR RegistryKeyPath endswithCIS "\services.exe" OR RegistryKeyPath endswithCIS "\sihost.exe" OR RegistryKeyPath endswithCIS "\svchost.exe" OR RegistryKeyPath endswithCIS "\taskhostw.exe" OR RegistryKeyPath endswithCIS "\winlogon.exe" OR RegistryKeyPath endswithCIS "\WmiPrvSe.exe")))

```