# proc_creation_win_susp_ntfs_short_name_use_cli

## Title
Use NTFS Short Name in Command Line

## ID
dd6b39d9-d9be-4a3b-8fe0-fe3c6a5c1795

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-05

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection

## References
https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
https://twitter.com/jonasLyk/status/1555914501802921984

## False Positives
Applications could use this notation occasionally which might generate some false positives. In that case Investigate the parent and child process.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "~1.exe" OR TgtProcCmdLine containsCIS "~1.bat" OR TgtProcCmdLine containsCIS "~1.msi" OR TgtProcCmdLine containsCIS "~1.vbe" OR TgtProcCmdLine containsCIS "~1.vbs" OR TgtProcCmdLine containsCIS "~1.dll" OR TgtProcCmdLine containsCIS "~1.ps1" OR TgtProcCmdLine containsCIS "~1.js" OR TgtProcCmdLine containsCIS "~1.hta" OR TgtProcCmdLine containsCIS "~2.exe" OR TgtProcCmdLine containsCIS "~2.bat" OR TgtProcCmdLine containsCIS "~2.msi" OR TgtProcCmdLine containsCIS "~2.vbe" OR TgtProcCmdLine containsCIS "~2.vbs" OR TgtProcCmdLine containsCIS "~2.dll" OR TgtProcCmdLine containsCIS "~2.ps1" OR TgtProcCmdLine containsCIS "~2.js" OR TgtProcCmdLine containsCIS "~2.hta") AND (NOT ((SrcProcImagePath endswithCIS "\WebEx\WebexHost.exe" OR SrcProcImagePath endswithCIS "\thor\thor64.exe") OR TgtProcCmdLine containsCIS "C:\xampp\vcredist\VCREDI~1.EXE"))))

```