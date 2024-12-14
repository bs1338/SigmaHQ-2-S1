# registry_set_asep_reg_keys_modification_office

## Title
Office Autorun Keys Modification

## ID
baecf8fb-edbf-429f-9ade-31fc3f22b970

## Author
Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)

## Date
2019-10-25

## Tags
attack.persistence, attack.t1547.001

## Description
Detects modification of autostart extensibility point (ASEP) in registry.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
Legitimate administrator sets up autorun keys for legitimate reason

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Software\Wow6432Node\Microsoft\Office" OR RegistryKeyPath containsCIS "\Software\Microsoft\Office") AND (RegistryKeyPath containsCIS "\Word\Addins" OR RegistryKeyPath containsCIS "\PowerPoint\Addins" OR RegistryKeyPath containsCIS "\Outlook\Addins" OR RegistryKeyPath containsCIS "\Onenote\Addins" OR RegistryKeyPath containsCIS "\Excel\Addins" OR RegistryKeyPath containsCIS "\Access\Addins" OR RegistryKeyPath containsCIS "test\Special\Perf") AND (NOT ((SrcProcImagePath = "C:\Program Files\AVG\Antivirus\RegSvr.exe" AND RegistryKeyPath containsCIS "\Microsoft\Office\Outlook\Addins\Antivirus.AsOutExt\") OR RegistryValue = "(Empty)" OR ((SrcProcImagePath startswithCIS "C:\Program Files\Microsoft Office\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft Office\" OR SrcProcImagePath startswithCIS "C:\Windows\System32\msiexec.exe" OR SrcProcImagePath startswithCIS "C:\Windows\System32\regsvr32.exe") AND (RegistryKeyPath containsCIS "\Excel\Addins\AdHocReportingExcelClientLib.AdHocReportingExcelClientAddIn.1\" OR RegistryKeyPath containsCIS "\Excel\Addins\ExcelPlugInShell.PowerMapConnect\" OR RegistryKeyPath containsCIS "\Excel\Addins\NativeShim\" OR RegistryKeyPath containsCIS "\Excel\Addins\NativeShim.InquireConnector.1\" OR RegistryKeyPath containsCIS "\Excel\Addins\PowerPivotExcelClientAddIn.NativeEntry.1\" OR RegistryKeyPath containsCIS "\Outlook\AddIns\AccessAddin.DC\" OR RegistryKeyPath containsCIS "\Outlook\AddIns\ColleagueImport.ColleagueImportAddin\" OR RegistryKeyPath containsCIS "\Outlook\AddIns\EvernoteCC.EvernoteContactConnector\" OR RegistryKeyPath containsCIS "\Outlook\AddIns\EvernoteOLRD.Connect\" OR RegistryKeyPath containsCIS "\Outlook\Addins\Microsoft.VbaAddinForOutlook.1\" OR RegistryKeyPath containsCIS "\Outlook\Addins\OcOffice.OcForms\" OR RegistryKeyPath containsCIS "\Outlook\Addins\OneNote.OutlookAddin" OR RegistryKeyPath containsCIS "\Outlook\Addins\OscAddin.Connect\" OR RegistryKeyPath containsCIS "\Outlook\Addins\OutlookChangeNotifier.Connect\" OR RegistryKeyPath containsCIS "\Outlook\Addins\UCAddin.LyncAddin.1" OR RegistryKeyPath containsCIS "\Outlook\Addins\UCAddin.UCAddin.1" OR RegistryKeyPath containsCIS "\Outlook\Addins\UmOutlookAddin.FormRegionAddin\")) OR (SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\" OR SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Updates\"))))))

```