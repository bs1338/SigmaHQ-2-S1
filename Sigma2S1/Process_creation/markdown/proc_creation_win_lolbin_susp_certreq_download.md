# proc_creation_win_lolbin_susp_certreq_download

## Title
Suspicious Certreq Command to Download

## ID
4480827a-9799-4232-b2c4-ccc6c4e9e12b

## Author
Christian Burkard (Nextron Systems)

## Date
2021-11-24

## Tags
attack.command-and-control, attack.t1105

## Description
Detects a suspicious certreq execution taken from the LOLBAS examples, which can be abused to download (small) files

## References
https://lolbas-project.github.io/lolbas/Binaries/Certreq/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -Post " AND TgtProcCmdLine containsCIS " -config " AND TgtProcCmdLine containsCIS " http" AND TgtProcCmdLine containsCIS " C:\windows\win.ini ") AND TgtProcImagePath endswithCIS "\certreq.exe"))

```