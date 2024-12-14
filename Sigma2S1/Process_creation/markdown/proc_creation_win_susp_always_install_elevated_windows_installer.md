# proc_creation_win_susp_always_install_elevated_windows_installer

## Title
Always Install Elevated Windows Installer

## ID
cd951fdc-4b2f-47f5-ba99-a33bf61e3770

## Author
Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community

## Date
2020-10-13

## Tags
attack.privilege-escalation, attack.t1548.002

## Description
Detects Windows Installer service (msiexec.exe) trying to install MSI packages with SYSTEM privilege

## References
https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-48-638.jpg

## False Positives
System administrator usage
Anti virus products
WindowsApps located in "C:\Program Files\WindowsApps\"

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((TgtProcImagePath containsCIS "\Windows\Installer\" AND TgtProcImagePath containsCIS "msi") AND TgtProcImagePath endswithCIS "tmp") OR (TgtProcImagePath endswithCIS "\msiexec.exe" AND (TgtProcIntegrityLevel In ("System","S-1-16-16384")))) AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI") AND (NOT ((SrcProcImagePath startswithCIS "C:\Program Files\Avast Software\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Avast Software\") OR SrcProcImagePath startswithCIS "C:\ProgramData\Avira\" OR (SrcProcImagePath startswithCIS "C:\Program Files\Google\Update\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Google\Update\") OR SrcProcImagePath = "C:\Windows\System32\services.exe" OR (TgtProcCmdLine endswithCIS "\system32\msiexec.exe /V" OR SrcProcCmdLine endswithCIS "\system32\msiexec.exe /V") OR SrcProcImagePath startswithCIS "C:\ProgramData\Sophos\"))))

```