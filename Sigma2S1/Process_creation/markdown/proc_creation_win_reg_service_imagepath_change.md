# proc_creation_win_reg_service_imagepath_change

## Title
Changing Existing Service ImagePath Value Via Reg.EXE

## ID
9b0b7ac3-6223-47aa-a3fd-e8f211e637db

## Author
frack113

## Date
2021-12-30

## Tags
attack.persistence, attack.t1574.011

## Description
Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.011/T1574.011.md#atomic-test-2---service-imagepath-change-with-regexe

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "add " AND TgtProcCmdLine containsCIS "SYSTEM\CurrentControlSet\Services\" AND TgtProcCmdLine containsCIS " ImagePath ") AND TgtProcImagePath endswithCIS "\reg.exe") AND (TgtProcCmdLine containsCIS " -d " OR TgtProcCmdLine containsCIS " /d " OR TgtProcCmdLine containsCIS " â€“d " OR TgtProcCmdLine containsCIS " â€”d " OR TgtProcCmdLine containsCIS " â€•d ")))

```