# proc_creation_win_certoc_download_direct_ip

## Title
File Download From IP Based URL Via CertOC.EXE

## ID
b86f6dea-0b2f-41f5-bdcc-a057bd19cd6a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-10-18

## Tags
attack.command-and-control, attack.execution, attack.t1105

## Description
Detects when a user downloads a file from an IP based URL using CertOC.exe

## References
https://lolbas-project.github.io/lolbas/Binaries/Certoc/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "-GetCACAPS" AND TgtProcImagePath endswithCIS "\certoc.exe" AND TgtProcCmdLine RegExp "://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"))

```