# proc_creation_win_registry_office_disable_python_security_warnings

## Title
Python Function Execution Security Warning Disabled In Excel

## ID
023c654f-8f16-44d9-bb2b-00ff36a62af9

## Author
@Kostastsale

## Date
2023-08-22

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
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " 0" AND (TgtProcCmdLine containsCIS "\Microsoft\Office\" AND TgtProcCmdLine containsCIS "\Excel\Security" AND TgtProcCmdLine containsCIS "PythonFunctionWarnings")))

```