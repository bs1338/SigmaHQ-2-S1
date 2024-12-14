# proc_creation_win_reg_enable_windows_recall

## Title
Windows Recall Feature Enabled Via Reg.EXE

## ID
817f252c-5143-4dae-b418-48c3e9f63728

## Author
Sajid Nawaz Khan

## Date
2024-06-02

## Tags
attack.collection, attack.t1113

## Description
Detects the enabling of the Windows Recall feature via registry manipulation.
 Windows Recall can be enabled by deleting the existing "DisableAIDataAnalysis" value, or setting it to 0.
Adversaries may enable Windows Recall as part of post-exploitation discovery and collection activities.
This rule assumes that Recall is already explicitly disabled on the host, and subsequently enabled by the adversary.


## References
https://learn.microsoft.com/en-us/windows/client-management/manage-recall
https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis

## False Positives
Legitimate use/activation of Windows Recall

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\reg.exe" AND (TgtProcCmdLine containsCIS "Microsoft\Windows\WindowsAI" AND TgtProcCmdLine containsCIS "DisableAIDataAnalysis") AND ((TgtProcCmdLine containsCIS "add" OR TgtProcCmdLine containsCIS "0") OR TgtProcCmdLine containsCIS "delete")))

```