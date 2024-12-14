# proc_creation_win_dns_susp_child_process

## Title
Unusual Child Process of dns.exe

## ID
a4e3d776-f12e-42c2-8510-9e6ed1f43ec3

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-27

## Tags
attack.initial-access, attack.t1133

## Description
Detects an unexpected process spawning from dns.exe which may indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)

## References
https://www.elastic.co/guide/en/security/current/unusual-child-process-of-dns-exe.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\dns.exe" AND (NOT TgtProcImagePath endswithCIS "\conhost.exe")))

```