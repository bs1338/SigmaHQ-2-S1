# file_delete_win_unusual_deletion_by_dns_exe

## Title
Unusual File Deletion by Dns.exe

## ID
8f0b1fb1-9bd4-4e74-8cdf-a8de4d2adfd0

## Author
Tim Rauch (Nextron Systems), Elastic (idea)

## Date
2022-09-27

## Tags
attack.initial-access, attack.t1133

## Description
Detects an unexpected file being deleted by dns.exe which my indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)

## References
https://www.elastic.co/guide/en/security/current/unusual-file-modification-by-dns-exe.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\dns.exe" AND (NOT TgtFilePath endswithCIS "\dns.log")))

```