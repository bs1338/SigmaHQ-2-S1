# registry_set_enable_windows_recall

## Title
Windows Recall Feature Enabled - Registry

## ID
75180c5f-4ea1-461a-a4f6-6e4700c065d4

## Author
Sajid Nawaz Khan

## Date
2024-06-02

## Tags
attack.collection, attack.t1113

## Description
Detects the enabling of the Windows Recall feature via registry manipulation. Windows Recall can be enabled by setting the value of "DisableAIDataAnalysis" to "0".
Adversaries may enable Windows Recall as part of post-exploitation discovery and collection activities.
This rule assumes that Recall is already explicitly disabled on the host, and subsequently enabled by the adversary.


## References
https://learn.microsoft.com/en-us/windows/client-management/manage-recall
https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis

## False Positives
Legitimate use/activation of Windows Recall

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath endswithCIS "\Software\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis"))

```