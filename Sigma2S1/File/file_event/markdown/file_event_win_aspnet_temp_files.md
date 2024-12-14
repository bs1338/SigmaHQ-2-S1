# file_event_win_aspnet_temp_files

## Title
Assembly DLL Creation Via AspNetCompiler

## ID
4c7f49ee-2638-43bb-b85b-ce676c30b260

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-14

## Tags
attack.execution

## Description
Detects the creation of new DLL assembly files by "aspnet_compiler.exe", which could be a sign of "aspnet_compiler" abuse to proxy execution through a build provider.


## References
Internal Research

## False Positives
Legitimate assembly compilation using a build provider

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\aspnet_compiler.exe" AND (TgtFilePath containsCIS "\Temporary ASP.NET Files\" AND TgtFilePath containsCIS "\assembly\tmp\" AND TgtFilePath containsCIS ".dll")))

```