# registry_set_policies_associations_tamper

## Title
Potential Attachment Manager Settings Associations Tamper

## ID
a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-01

## Tags
attack.defense-evasion

## Description
Detects tampering with attachment manager settings policies associations to lower the default file type risks (See reference for more information)

## References
https://support.microsoft.com/en-us/topic/information-about-the-attachment-manager-in-microsoft-windows-c48a4dcd-8de5-2af5-ee9b-cd795ae42738
https://www.virustotal.com/gui/file/2bcd5702a7565952c44075ac6fb946c7780526640d1264f692c7664c02c68465

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations\" AND ((RegistryValue = "DWORD (0x00006152)" AND RegistryKeyPath endswithCIS "\DefaultFileTypeRisk") OR ((RegistryValue containsCIS ".zip;" OR RegistryValue containsCIS ".rar;" OR RegistryValue containsCIS ".exe;" OR RegistryValue containsCIS ".bat;" OR RegistryValue containsCIS ".com;" OR RegistryValue containsCIS ".cmd;" OR RegistryValue containsCIS ".reg;" OR RegistryValue containsCIS ".msi;" OR RegistryValue containsCIS ".htm;" OR RegistryValue containsCIS ".html;") AND RegistryKeyPath endswithCIS "\LowRiskFileTypes"))))

```