# registry_delete_enable_windows_recall

## Title
Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted

## ID
5dfc1465-8f65-4fde-8eb5-6194380c6a62

## Author
Sajid Nawaz Khan

## Date
2024-06-02

## Tags
attack.collection, attack.t1113

## Description
Detects the enabling of the Windows Recall feature via registry manipulation. Windows Recall can be enabled by deleting the existing "DisableAIDataAnalysis" registry value.
Adversaries may enable Windows Recall as part of post-exploitation discovery and collection activities.
This rule assumes that Recall is already explicitly disabled on the host, and subsequently enabled by the adversary.


## References
https://learn.microsoft.com/en-us/windows/client-management/manage-recall
https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis

## False Positives
Legitimate use/activation of Windows Recall

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "DeleteValue" AND RegistryKeyPath endswithCIS "\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis"))

```