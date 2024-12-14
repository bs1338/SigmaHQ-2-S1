# registry_set_disable_macroruntimescanscope

## Title
Disable Macro Runtime Scan Scope

## ID
ab871450-37dc-4a3a-997f-6662aa8ae0f1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-25

## Tags
attack.defense-evasion

## Description
Detects tampering with the MacroRuntimeScanScope registry key to disable runtime scanning of enabled macros

## References
https://www.microsoft.com/en-us/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/
https://admx.help/?Category=Office2016&Policy=office16.Office.Microsoft.Policies.Windows::L_MacroRuntimeScanScope
https://github.com/S3cur3Th1sSh1t/OffensiveVBA/blob/28cc6a2802d8176195ac19b3c8e9a749009a82a3/src/AMSIbypasses.vba

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath containsCIS "\SOFTWARE\" AND RegistryKeyPath containsCIS "\Microsoft\Office\" AND RegistryKeyPath containsCIS "\Common\Security") AND RegistryKeyPath endswithCIS "\MacroRuntimeScanScope"))

```