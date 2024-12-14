# registry_set_persistence_shim_database_uncommon_location

## Title
Potential Persistence Via Shim Database In Uncommon Location

## ID
6b6976a3-b0e6-4723-ac24-ae38a737af41

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-01

## Tags
attack.persistence, attack.t1546.011

## Description
Detects the installation of a new shim database where the file is located in a non-default location

## References
https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
https://andreafortuna.org/2018/11/12/process-injection-and-persistence-using-application-shimming/
https://www.blackhat.com/docs/asia-14/materials/Erickson/Asia-14-Erickson-Persist-It-Using-And-Abusing-Microsofts-Fix-It-Patches.pdf

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\" AND RegistryKeyPath containsCIS "\DatabasePath") AND (NOT RegistryValue containsCIS ":\Windows\AppPatch\Custom")))

```