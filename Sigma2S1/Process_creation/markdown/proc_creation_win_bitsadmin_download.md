# proc_creation_win_bitsadmin_download

## Title
File Download Via Bitsadmin

## ID
d059842b-6b9d-4ed1-b5c3-5b89143c6ede

## Author
Michael Haag, FPT.EagleEye

## Date
2017-03-09

## Tags
attack.defense-evasion, attack.persistence, attack.t1197, attack.s0190, attack.t1036.003

## Description
Detects usage of bitsadmin downloading a file

## References
https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
https://isc.sans.edu/diary/22264
https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/

## False Positives
Some legitimate apps use this, but limited.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\bitsadmin.exe" AND (TgtProcCmdLine containsCIS " /transfer " OR ((TgtProcCmdLine containsCIS " /create " OR TgtProcCmdLine containsCIS " /addfile ") AND TgtProcCmdLine containsCIS "http"))))

```