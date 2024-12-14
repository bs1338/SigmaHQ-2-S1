# registry_set_persistence_office_vsto

## Title
Potential Persistence Via Visual Studio Tools for Office

## ID
9d15044a-7cfe-4d23-8085-6ebc11df7685

## Author
Bhabesh Raj

## Date
2021-01-10

## Tags
attack.t1137.006, attack.persistence

## Description
Detects persistence via Visual Studio Tools for Office (VSTO) add-ins in Office applications.

## References
https://twitter.com/_vivami/status/1347925307643355138
https://vanmieghem.io/stealth-outlook-persistence/

## False Positives
Legitimate Addin Installation

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Software\Microsoft\Office\Outlook\Addins\" OR RegistryKeyPath containsCIS "\Software\Microsoft\Office\Word\Addins\" OR RegistryKeyPath containsCIS "\Software\Microsoft\Office\Excel\Addins\" OR RegistryKeyPath containsCIS "\Software\Microsoft\Office\Powerpoint\Addins\" OR RegistryKeyPath containsCIS "\Software\Microsoft\VSTO\Security\Inclusion\") AND (NOT ((SrcProcImagePath = "C:\Program Files\AVG\Antivirus\RegSvr.exe" AND RegistryKeyPath containsCIS "\Microsoft\Office\Outlook\Addins\Antivirus.AsOutExt\") OR (SrcProcImagePath endswithCIS "\msiexec.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe") OR (SrcProcImagePath endswithCIS "\excel.exe" OR SrcProcImagePath endswithCIS "\integrator.exe" OR SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" OR SrcProcImagePath endswithCIS "\winword.exe" OR SrcProcImagePath endswithCIS "\visio.exe") OR SrcProcImagePath endswithCIS "\Teams.exe"))))

```