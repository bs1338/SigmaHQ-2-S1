# proc_creation_win_mshta_http

## Title
Remotely Hosted HTA File Executed Via Mshta.EXE

## ID
b98d0db6-511d-45de-ad02-e82a98729620

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-08

## Tags
attack.defense-evasion, attack.execution, attack.t1218.005

## Description
Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file

## References
https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://" OR TgtProcCmdLine containsCIS "ftp://") AND TgtProcImagePath endswithCIS "\mshta.exe"))

```