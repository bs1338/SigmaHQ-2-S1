# proc_creation_win_wmic_recon_csproduct

## Title
Hardware Model Reconnaissance Via Wmic.EXE

## ID
3e3ceccd-6c06-48b8-b5ff-ab1d25db8c1d

## Author
Florian Roth (Nextron Systems)

## Date
2023-02-14

## Tags
attack.execution, attack.t1047, car.2016-03-002

## Description
Detects the execution of WMIC with the "csproduct" which is used to obtain information such as hardware models and vendor information

## References
https://jonconwayuk.wordpress.com/2014/01/31/wmic-csproduct-using-wmi-to-identify-make-and-model-of-hardware/
https://www.uptycs.com/blog/kuraystealer-a-bandit-using-discord-webhooks

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "csproduct" AND TgtProcImagePath endswithCIS "\wmic.exe"))

```