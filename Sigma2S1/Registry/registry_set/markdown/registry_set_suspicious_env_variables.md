# registry_set_suspicious_env_variables

## Title
Suspicious Environment Variable Has Been Registered

## ID
966315ef-c5e1-4767-ba25-fce9c8de3660

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-20

## Tags
attack.defense-evasion, attack.persistence

## Description
Detects the creation of user-specific or system-wide environment variables via the registry. Which contains suspicious commands and strings

## References
https://infosec.exchange/@sbousseaden/109542254124022664

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue In Contains AnyCase ("powershell","pwsh")) OR (RegistryValue containsCIS "\AppData\Local\Temp\" OR RegistryValue containsCIS "C:\Users\Public\" OR RegistryValue containsCIS "TVqQAAMAAAAEAAAA" OR RegistryValue containsCIS "TVpQAAIAAAAEAA8A" OR RegistryValue containsCIS "TVqAAAEAAAAEABAA" OR RegistryValue containsCIS "TVoAAAAAAAAAAAAA" OR RegistryValue containsCIS "TVpTAQEAAAAEAAAA" OR RegistryValue containsCIS "SW52b2tlL" OR RegistryValue containsCIS "ludm9rZS" OR RegistryValue containsCIS "JbnZva2Ut" OR RegistryValue containsCIS "SQBuAHYAbwBrAGUALQ" OR RegistryValue containsCIS "kAbgB2AG8AawBlAC0A" OR RegistryValue containsCIS "JAG4AdgBvAGsAZQAtA") OR (RegistryValue startswithCIS "SUVY" OR RegistryValue startswithCIS "SQBFAF" OR RegistryValue startswithCIS "SQBuAH" OR RegistryValue startswithCIS "cwBhA" OR RegistryValue startswithCIS "aWV4" OR RegistryValue startswithCIS "aQBlA" OR RegistryValue startswithCIS "R2V0" OR RegistryValue startswithCIS "dmFy" OR RegistryValue startswithCIS "dgBhA" OR RegistryValue startswithCIS "dXNpbm" OR RegistryValue startswithCIS "H4sIA" OR RegistryValue startswithCIS "Y21k" OR RegistryValue startswithCIS "cABhAH" OR RegistryValue startswithCIS "Qzpc" OR RegistryValue startswithCIS "Yzpc")) AND RegistryKeyPath containsCIS "\Environment\"))

```