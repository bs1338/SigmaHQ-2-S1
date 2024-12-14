# registry_set_persistence_shim_database

## Title
Potential Persistence Via Shim Database Modification

## ID
dfb5b4e8-91d0-4291-b40a-e3b0d3942c45

## Author
frack113

## Date
2021-12-30

## Tags
attack.persistence, attack.t1546.011

## Description
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.011/T1546.011.md#atomic-test-3---registry-key-creation-andor-modification-events-for-sdb
https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
https://andreafortuna.org/2018/11/12/process-injection-and-persistence-using-application-shimming/

## False Positives
Legitimate custom SHIM installations will also trigger this rule

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\") AND (NOT RegistryValue = "")))

```