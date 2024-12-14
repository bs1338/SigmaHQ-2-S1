# proc_creation_win_fltmc_unload_driver

## Title
Filter Driver Unloaded Via Fltmc.EXE

## ID
4931188c-178e-4ee7-a348-39e8a7a56821

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-13

## Tags
attack.defense-evasion, attack.t1070, attack.t1562, attack.t1562.002

## Description
Detect filter driver unloading activity via fltmc.exe

## References
https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon
https://www.cybereason.com/blog/threat-analysis-report-lockbit-2.0-all-paths-lead-to-ransom

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "unload" AND TgtProcImagePath endswithCIS "\fltMC.exe") AND (NOT ((TgtProcCmdLine endswithCIS "unload rtp_filesystem_filter" AND SrcProcImagePath containsCIS "\AppData\Local\Temp\" AND SrcProcImagePath endswithCIS "\endpoint-protection-installer-x64.tmp" AND SrcProcImagePath startswithCIS "C:\Users\") OR (TgtProcCmdLine endswithCIS "unload DFMFilter" AND SrcProcImagePath = "C:\Program Files (x86)\ManageEngine\uems_agent\bin\dcfaservice64.exe")))))

```