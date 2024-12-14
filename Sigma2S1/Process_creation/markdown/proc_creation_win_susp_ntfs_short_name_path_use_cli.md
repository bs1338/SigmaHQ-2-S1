# proc_creation_win_susp_ntfs_short_name_path_use_cli

## Title
Use Short Name Path in Command Line

## ID
349d891d-fef0-4fe4-bc53-eee623a15969

## Author
frack113, Nasreddine Bencherchali

## Date
2022-08-07

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection

## References
https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
https://twitter.com/frack113/status/1555830623633375232

## False Positives
Applications could use this notation occasionally which might generate some false positives. In that case investigate the parent and child process.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "~1\" OR TgtProcCmdLine containsCIS "~2\") AND (NOT ((SrcProcImagePath In Contains AnyCase ("C:\Windows\System32\Dism.exe","C:\Windows\System32\cleanmgr.exe","C:\Program Files\GPSoftware\Directory Opus\dopus.exe")) OR (SrcProcImagePath endswithCIS "\WebEx\WebexHost.exe" OR SrcProcImagePath endswithCIS "\thor\thor64.exe" OR SrcProcImagePath endswithCIS "\veam.backup.shell.exe" OR SrcProcImagePath endswithCIS "\winget.exe" OR SrcProcImagePath endswithCIS "\Everything\Everything.exe") OR SrcProcImagePath containsCIS "\AppData\Local\Temp\WinGet\" OR (TgtProcCmdLine containsCIS "\appdata\local\webex\webex64\meetings\wbxreport.exe" OR TgtProcCmdLine containsCIS "C:\Program Files\Git\post-install.bat" OR TgtProcCmdLine containsCIS "C:\Program Files\Git\cmd\scalar.exe")))))

```