# registry_set_office_trusted_location_uncommon

## Title
Uncommon Microsoft Office Trusted Location Added

## ID
f742bde7-9528-42e5-bd82-84f51a8387d2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-21

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects changes to registry keys related to "Trusted Location" of Microsoft Office where the path is set to something uncommon. Attackers might add additional trusted locations to avoid macro security restrictions.

## References
Internal Research
https://admx.help/?Category=Office2016&Policy=excel16.Office.Microsoft.Policies.Windows::L_TrustedLoc01

## False Positives
Other unknown legitimate or custom paths need to be filtered to avoid false positives

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "Security\Trusted Locations\Location" AND RegistryKeyPath endswithCIS "\Path") AND (NOT ((SrcProcImagePath containsCIS ":\Program Files\Microsoft Office\" OR SrcProcImagePath containsCIS ":\Program Files (x86)\Microsoft Office\") OR (SrcProcImagePath containsCIS ":\Program Files\Common Files\Microsoft Shared\ClickToRun\" AND SrcProcImagePath endswithCIS "\OfficeClickToRun.exe"))) AND (NOT (RegistryValue containsCIS "%APPDATA%\Microsoft\Templates" OR RegistryValue containsCIS "%%APPDATA%%\Microsoft\Templates" OR RegistryValue containsCIS "%APPDATA%\Microsoft\Word\Startup" OR RegistryValue containsCIS "%%APPDATA%%\Microsoft\Word\Startup" OR RegistryValue containsCIS ":\Program Files (x86)\Microsoft Office\root\Templates\" OR RegistryValue containsCIS ":\Program Files\Microsoft Office (x86)\Templates" OR RegistryValue containsCIS ":\Program Files\Microsoft Office\root\Templates\" OR RegistryValue containsCIS ":\Program Files\Microsoft Office\Templates\"))))

```