# file_event_win_hktl_mimikatz_files

## Title
HackTool - Mimikatz Kirbi File Creation

## ID
9e099d99-44c2-42b6-a6d8-54c3545cab29

## Author
Florian Roth (Nextron Systems), David ANDRE

## Date
2021-11-08

## Tags
attack.credential-access, attack.t1558

## Description
Detects the creation of files created by mimikatz such as ".kirbi", "mimilsa.log", etc.

## References
https://cobalt.io/blog/kerberoast-attack-techniques
https://pentestlab.blog/2019/10/21/persistence-security-support-provider/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".kirbi" OR TgtFilePath endswithCIS "mimilsa.log"))

```