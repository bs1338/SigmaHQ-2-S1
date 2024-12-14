# proc_creation_win_susp_inline_base64_mz_header

## Title
Base64 MZ Header In CommandLine

## ID
22e58743-4ac8-4a9f-bf19-00a0428d8c5f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-12

## Tags
attack.execution

## Description
Detects encoded base64 MZ header in the commandline

## References
https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "TVqQAAMAAAAEAAAA" OR TgtProcCmdLine containsCIS "TVpQAAIAAAAEAA8A" OR TgtProcCmdLine containsCIS "TVqAAAEAAAAEABAA" OR TgtProcCmdLine containsCIS "TVoAAAAAAAAAAAAA" OR TgtProcCmdLine containsCIS "TVpTAQEAAAAEAAAA"))

```