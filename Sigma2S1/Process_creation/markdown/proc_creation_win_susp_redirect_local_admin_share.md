# proc_creation_win_susp_redirect_local_admin_share

## Title
Suspicious Redirection to Local Admin Share

## ID
ab9e3b40-0c85-4ba1-aede-455d226fd124

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-16

## Tags
attack.exfiltration, attack.t1048

## Description
Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers

## References
https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ">" AND (TgtProcCmdLine containsCIS "\\127.0.0.1\admin$\" OR TgtProcCmdLine containsCIS "\\localhost\admin$\")))

```