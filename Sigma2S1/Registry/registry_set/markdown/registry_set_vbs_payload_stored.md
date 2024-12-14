# registry_set_vbs_payload_stored

## Title
VBScript Payload Stored in Registry

## ID
46490193-1b22-4c29-bdd6-5bf63907216f

## Author
Florian Roth (Nextron Systems)

## Date
2021-03-05

## Tags
attack.persistence, attack.t1547.001

## Description
Detects VBScript content stored into registry keys as seen being used by UNC2452 group

## References
https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue containsCIS "vbscript:" OR RegistryValue containsCIS "jscript:" OR RegistryValue containsCIS "mshtml," OR RegistryValue containsCIS "RunHTMLApplication" OR RegistryValue containsCIS "Execute(" OR RegistryValue containsCIS "CreateObject" OR RegistryValue containsCIS "window.close") AND RegistryKeyPath containsCIS "Software\Microsoft\Windows\CurrentVersion") AND (NOT (RegistryKeyPath containsCIS "Software\Microsoft\Windows\CurrentVersion\Run" OR ((RegistryValue containsCIS "\Microsoft.NET\Primary Interop Assemblies\Microsoft.mshtml.dll" OR RegistryValue containsCIS "<\Microsoft.mshtml,fileVersion=" OR RegistryValue containsCIS "_mshtml_dll_" OR RegistryValue containsCIS "<\Microsoft.mshtml,culture=") AND SrcProcImagePath endswithCIS "\msiexec.exe" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\")))))

```