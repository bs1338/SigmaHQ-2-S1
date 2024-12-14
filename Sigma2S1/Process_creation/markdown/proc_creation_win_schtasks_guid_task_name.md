# proc_creation_win_schtasks_guid_task_name

## Title
Suspicious Scheduled Task Name As GUID

## ID
ff2fff64-4cd6-4a2b-ba7d-e28a30bbe66b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-31

## Tags
attack.execution, attack.t1053.005

## Description
Detects creation of a scheduled task with a GUID like name

## References
https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/

## False Positives
Legitimate software naming their tasks as GUIDs

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "}\"" OR TgtProcCmdLine containsCIS "}'" OR TgtProcCmdLine containsCIS "} ") AND (TgtProcCmdLine containsCIS "/Create " AND TgtProcImagePath endswithCIS "\schtasks.exe") AND (TgtProcCmdLine containsCIS "/TN \"{" OR TgtProcCmdLine containsCIS "/TN '{" OR TgtProcCmdLine containsCIS "/TN {")))

```