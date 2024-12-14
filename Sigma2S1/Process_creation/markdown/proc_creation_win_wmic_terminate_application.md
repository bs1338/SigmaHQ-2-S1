# proc_creation_win_wmic_terminate_application

## Title
Application Terminated Via Wmic.EXE

## ID
49d9671b-0a0a-4c09-8280-d215bfd30662

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-11

## Tags
attack.execution, attack.t1047

## Description
Detects calls to the "terminate" function via wmic in order to kill an application

## References
https://cyble.com/blog/lockfile-ransomware-using-proxyshell-attack-to-deploy-ransomware/
https://www.bitdefender.com/files/News/CaseStudies/study/377/Bitdefender-Whitepaper-WMI-creat4871-en-EN-GenericUse.pdf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "call" AND TgtProcCmdLine containsCIS "terminate") AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```