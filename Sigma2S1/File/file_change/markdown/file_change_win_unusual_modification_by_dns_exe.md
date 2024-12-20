# file_change_win_unusual_modification_by_dns_exe

## Title
Unusual File Modification by dns.exe

## ID
9f383dc0-fdeb-4d56-acbc-9f9f4f8f20f3

## Author
Tim Rauch (Nextron Systems), Elastic (idea)

## Date
2022-09-27

## Tags
attack.initial-access, attack.t1133

## Description
Detects an unexpected file being modified by dns.exe which my indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)

## References
https://www.elastic.co/guide/en/security/current/unusual-file-modification-by-dns-exe.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "File Modification" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\dns.exe" AND (NOT TgtFilePath endswithCIS "\dns.log")))

```