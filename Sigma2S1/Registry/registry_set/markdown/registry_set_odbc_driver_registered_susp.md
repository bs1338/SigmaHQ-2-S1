# registry_set_odbc_driver_registered_susp

## Title
Potentially Suspicious ODBC Driver Registered

## ID
e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-23

## Tags
attack.persistence, attack.t1003

## Description
Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location

## References
https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS ":\PerfLogs\" OR RegistryValue containsCIS ":\ProgramData\" OR RegistryValue containsCIS ":\Temp\" OR RegistryValue containsCIS ":\Users\Public\" OR RegistryValue containsCIS ":\Windows\Registration\CRMLog" OR RegistryValue containsCIS ":\Windows\System32\com\dmp\" OR RegistryValue containsCIS ":\Windows\System32\FxsTmp\" OR RegistryValue containsCIS ":\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\" OR RegistryValue containsCIS ":\Windows\System32\spool\drivers\color\" OR RegistryValue containsCIS ":\Windows\System32\spool\PRINTERS\" OR RegistryValue containsCIS ":\Windows\System32\spool\SERVERS\" OR RegistryValue containsCIS ":\Windows\System32\Tasks_Migrated\" OR RegistryValue containsCIS ":\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\" OR RegistryValue containsCIS ":\Windows\SysWOW64\com\dmp\" OR RegistryValue containsCIS ":\Windows\SysWOW64\FxsTmp\" OR RegistryValue containsCIS ":\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\" OR RegistryValue containsCIS ":\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\" OR RegistryValue containsCIS ":\Windows\Tasks\" OR RegistryValue containsCIS ":\Windows\Temp\" OR RegistryValue containsCIS ":\Windows\Tracing\" OR RegistryValue containsCIS "\AppData\Local\Temp\" OR RegistryValue containsCIS "\AppData\Roaming\") AND RegistryKeyPath containsCIS "\SOFTWARE\ODBC\ODBCINST.INI\" AND (RegistryKeyPath endswithCIS "\Driver" OR RegistryKeyPath endswithCIS "\Setup")))

```