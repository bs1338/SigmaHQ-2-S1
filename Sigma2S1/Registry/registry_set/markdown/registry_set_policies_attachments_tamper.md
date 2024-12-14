# registry_set_policies_attachments_tamper

## Title
Potential Attachment Manager Settings Attachments Tamper

## ID
ee77a5db-b0f3-4be2-bfd4-b58be1c6b15a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-01

## Tags
attack.defense-evasion

## Description
Detects tampering with attachment manager settings policies attachments (See reference for more information)

## References
https://support.microsoft.com/en-us/topic/information-about-the-attachment-manager-in-microsoft-windows-c48a4dcd-8de5-2af5-ee9b-cd795ae42738
https://www.virustotal.com/gui/file/2bcd5702a7565952c44075ac6fb946c7780526640d1264f692c7664c02c68465

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" AND ((RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\HideZoneInfoOnProperties") OR (RegistryValue = "DWORD (0x00000002)" AND RegistryKeyPath endswithCIS "\SaveZoneInformation") OR (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\ScanWithAntiVirus"))))

```