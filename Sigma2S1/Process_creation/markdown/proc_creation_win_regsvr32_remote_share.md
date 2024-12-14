# proc_creation_win_regsvr32_remote_share

## Title
Suspicious Regsvr32 Execution From Remote Share

## ID
88a87a10-384b-4ad7-8871-2f9bf9259ce5

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-31

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects REGSVR32.exe to execute DLL hosted on remote shares

## References
https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " \\" AND TgtProcImagePath endswithCIS "\regsvr32.exe"))

```