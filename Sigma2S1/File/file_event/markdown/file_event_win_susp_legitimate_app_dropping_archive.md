# file_event_win_susp_legitimate_app_dropping_archive

## Title
Legitimate Application Dropped Archive

## ID
654fcc6d-840d-4844-9b07-2c3300e54a26

## Author
frack113, Florian Roth

## Date
2022-08-21

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects programs on a Windows system that should not write an archive to disk

## References
https://github.com/Neo23x0/sysmon-config/blob/3f808d9c022c507aae21a9346afba4a59dd533b9/sysmonconfig-export-block.xml#L1326

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\winword.exe" OR SrcProcImagePath endswithCIS "\excel.exe" OR SrcProcImagePath endswithCIS "\powerpnt.exe" OR SrcProcImagePath endswithCIS "\msaccess.exe" OR SrcProcImagePath endswithCIS "\mspub.exe" OR SrcProcImagePath endswithCIS "\eqnedt32.exe" OR SrcProcImagePath endswithCIS "\visio.exe" OR SrcProcImagePath endswithCIS "\wordpad.exe" OR SrcProcImagePath endswithCIS "\wordview.exe" OR SrcProcImagePath endswithCIS "\certutil.exe" OR SrcProcImagePath endswithCIS "\certoc.exe" OR SrcProcImagePath endswithCIS "\CertReq.exe" OR SrcProcImagePath endswithCIS "\Desktopimgdownldr.exe" OR SrcProcImagePath endswithCIS "\esentutl.exe" OR SrcProcImagePath endswithCIS "\finger.exe" OR SrcProcImagePath endswithCIS "\notepad.exe" OR SrcProcImagePath endswithCIS "\AcroRd32.exe" OR SrcProcImagePath endswithCIS "\RdrCEF.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\hh.exe") AND (TgtFilePath endswithCIS ".zip" OR TgtFilePath endswithCIS ".rar" OR TgtFilePath endswithCIS ".7z" OR TgtFilePath endswithCIS ".diagcab" OR TgtFilePath endswithCIS ".appx")))

```