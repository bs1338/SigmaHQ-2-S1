# file_event_win_susp_winsxs_binary_creation

## Title
WinSxS Executable File Creation By Non-System Process

## ID
34746e8c-5fb8-415a-b135-0abc167e912a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-11

## Tags
attack.execution

## Description
Detects the creation of binaries in the WinSxS folder by non-system processes

## References
https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS ".exe" AND TgtFilePath startswithCIS "C:\Windows\WinSxS\") AND (NOT (SrcProcImagePath startswithCIS "C:\Windows\Systems32\" OR SrcProcImagePath startswithCIS "C:\Windows\SysWOW64\" OR SrcProcImagePath startswithCIS "C:\Windows\WinSxS\"))))

```