# proc_creation_win_rundll32_udl_exec

## Title
Potentially Suspicious Rundll32.EXE Execution of UDL File

## ID
0ea52357-cd59-4340-9981-c46c7e900428

## Author
@kostastsale

## Date
2024-08-16

## Tags
attack.execution, attack.t1218.011, attack.t1071

## Description
Detects the execution of rundll32.exe with the oledb32.dll library to open a UDL file.
Threat actors can abuse this technique as a phishing vector to capture authentication credentials or other sensitive data.


## References
https://trustedsec.com/blog/oops-i-udld-it-again

## False Positives
UDL files serve as a convenient and flexible tool for managing and testing database connections in various development and administrative scenarios.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "oledb32.dll" AND TgtProcCmdLine containsCIS ",OpenDSLFile " AND TgtProcCmdLine = "*\Users\*\Downloads\*") AND TgtProcCmdLine endswithCIS ".udl") AND TgtProcImagePath endswithCIS "\rundll32.exe" AND SrcProcImagePath endswithCIS "\explorer.exe"))

```