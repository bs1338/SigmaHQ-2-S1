# file_event_win_susp_legitimate_app_dropping_exe

## Title
Legitimate Application Dropped Executable

## ID
f0540f7e-2db3-4432-b9e0-3965486744bc

## Author
frack113, Florian Roth (Nextron Systems)

## Date
2022-08-21

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects programs on a Windows system that should not write executables to disk

## References
https://github.com/Neo23x0/sysmon-config/blob/3f808d9c022c507aae21a9346afba4a59dd533b9/sysmonconfig-export-block.xml#L1326

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\eqnedt32.exe" OR SrcProcImagePath endswithCIS "\wordpad.exe" OR SrcProcImagePath endswithCIS "\wordview.exe" OR SrcProcImagePath endswithCIS "\certutil.exe" OR SrcProcImagePath endswithCIS "\certoc.exe" OR SrcProcImagePath endswithCIS "\CertReq.exe" OR SrcProcImagePath endswithCIS "\Desktopimgdownldr.exe" OR SrcProcImagePath endswithCIS "\esentutl.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\AcroRd32.exe" OR SrcProcImagePath endswithCIS "\RdrCEF.exe" OR SrcProcImagePath endswithCIS "\hh.exe" OR SrcProcImagePath endswithCIS "\finger.exe") AND (TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".ocx")))

```