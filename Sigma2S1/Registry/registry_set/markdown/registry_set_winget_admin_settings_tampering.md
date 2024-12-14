# registry_set_winget_admin_settings_tampering

## Title
Winget Admin Settings Modification

## ID
6db5eaf9-88f7-4ed9-af7d-9ef2ad12f236

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-17

## Tags
attack.defense-evasion, attack.persistence

## Description
Detects changes to the AppInstaller (winget) admin settings. Such as enabling local manifest installations or disabling installer hash checks

## References
https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
https://github.com/microsoft/winget-cli/blob/02d2f93807c9851d73eaacb4d8811a76b64b7b01/src/AppInstallerCommonCore/Public/winget/AdminSettings.h#L13

## False Positives
The event doesn't contain information about the type of change. False positives are expected with legitimate changes

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\winget.exe" AND RegistryKeyPath endswithCIS "\LocalState\admin_settings" AND RegistryKeyPath startswithCIS "\REGISTRY\A\"))

```