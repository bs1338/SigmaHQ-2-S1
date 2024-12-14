# registry_set_odbc_driver_registered

## Title
New ODBC Driver Registered

## ID
3390fbef-c98d-4bdd-a863-d65ed7c610dd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-23

## Tags
attack.persistence

## Description
Detects the registration of a new ODBC driver.

## References
https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/

## False Positives
Likely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SOFTWARE\ODBC\ODBCINST.INI\" AND RegistryKeyPath endswithCIS "\Driver") AND (NOT (RegistryValue = "%WINDIR%\System32\SQLSRV32.dll" AND RegistryKeyPath containsCIS "\SQL Server\")) AND (NOT ((RegistryValue endswithCIS "\ACEODBC.DLL" AND RegistryValue startswithCIS "C:\Progra" AND RegistryKeyPath containsCIS "\Microsoft Access ") OR (RegistryValue endswithCIS "\ACEODBC.DLL" AND RegistryValue startswithCIS "C:\Progra" AND RegistryKeyPath containsCIS "\Microsoft Excel Driver")))))

```