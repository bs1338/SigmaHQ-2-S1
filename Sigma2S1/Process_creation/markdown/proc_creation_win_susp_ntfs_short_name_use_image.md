# proc_creation_win_susp_ntfs_short_name_use_image

## Title
Use NTFS Short Name in Image

## ID
3ef5605c-9eb9-47b0-9a71-b727e6aa5c3b

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-06

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image based detection

## References
https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
https://twitter.com/jonasLyk/status/1555914501802921984

## False Positives
Software Installers

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "~1.bat" OR TgtProcImagePath containsCIS "~1.dll" OR TgtProcImagePath containsCIS "~1.exe" OR TgtProcImagePath containsCIS "~1.hta" OR TgtProcImagePath containsCIS "~1.js" OR TgtProcImagePath containsCIS "~1.msi" OR TgtProcImagePath containsCIS "~1.ps1" OR TgtProcImagePath containsCIS "~1.tmp" OR TgtProcImagePath containsCIS "~1.vbe" OR TgtProcImagePath containsCIS "~1.vbs" OR TgtProcImagePath containsCIS "~2.bat" OR TgtProcImagePath containsCIS "~2.dll" OR TgtProcImagePath containsCIS "~2.exe" OR TgtProcImagePath containsCIS "~2.hta" OR TgtProcImagePath containsCIS "~2.js" OR TgtProcImagePath containsCIS "~2.msi" OR TgtProcImagePath containsCIS "~2.ps1" OR TgtProcImagePath containsCIS "~2.tmp" OR TgtProcImagePath containsCIS "~2.vbe" OR TgtProcImagePath containsCIS "~2.vbs") AND (NOT SrcProcImagePath = "C:\Windows\explorer.exe") AND (NOT (SrcProcImagePath endswithCIS "\thor\thor64.exe" OR TgtProcImagePath endswithCIS "\VCREDI~1.EXE" OR SrcProcImagePath endswithCIS "\WebEx\WebexHost.exe" OR TgtProcImagePath = "C:\PROGRA~1\WinZip\WZPREL~1.EXE"))))

```