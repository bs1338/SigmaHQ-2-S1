# registry_set_office_disable_python_security_warnings

## Title
Python Function Execution Security Warning Disabled In Excel - Registry

## ID
17e53739-a1fc-4a62-b1b9-87711c2d5e44

## Author
Nasreddine Bencherchali (Nextron Systems), @Kostastsale

## Date
2024-08-23

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects changes to the registry value "PythonFunctionWarnings" that would prevent any warnings or alerts from showing when Python functions are about to be executed.
Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet.


## References
https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath containsCIS "\Microsoft\Office\" AND RegistryKeyPath endswithCIS "\Excel\Security\PythonFunctionWarnings"))

```