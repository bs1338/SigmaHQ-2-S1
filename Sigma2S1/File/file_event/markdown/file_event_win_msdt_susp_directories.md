# file_event_win_msdt_susp_directories

## Title
File Creation In Suspicious Directory By Msdt.EXE

## ID
318557a5-150c-4c8d-b70e-a9910e199857

## Author
Vadim Varganov, Florian Roth (Nextron Systems)

## Date
2022-08-24

## Tags
attack.persistence, attack.t1547.001, cve.2022-30190

## Description
Detects msdt.exe creating files in suspicious directories which could be a sign of exploitation of either Follina or Dogwalk vulnerabilities

## References
https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd
https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\msdt.exe" AND (TgtFilePath containsCIS "\Desktop\" OR TgtFilePath containsCIS "\Start Menu\Programs\Startup\" OR TgtFilePath containsCIS "C:\PerfLogs\" OR TgtFilePath containsCIS "C:\ProgramData\" OR TgtFilePath containsCIS "C:\Users\Public\")))

```