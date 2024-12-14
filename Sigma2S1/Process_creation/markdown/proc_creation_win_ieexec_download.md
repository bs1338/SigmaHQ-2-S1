# proc_creation_win_ieexec_download

## Title
File Download And Execution Via IEExec.EXE

## ID
9801abb8-e297-4dbf-9fbd-57dde0e830ad

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-05-16

## Tags
attack.command-and-control, attack.t1105

## Description
Detects execution of the IEExec utility to download and execute files

## References
https://lolbas-project.github.io/lolbas/Binaries/Ieexec/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\IEExec.exe"))

```