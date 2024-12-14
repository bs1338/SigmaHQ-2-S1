# proc_creation_win_susp_ntfs_short_name_path_use_image

## Title
Use Short Name Path in Image

## ID
a96970af-f126-420d-90e1-d37bf25e50e1

## Author
frack113, Nasreddine Bencherchali

## Date
2022-08-07

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image detection

## References
https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
https://twitter.com/frack113/status/1555830623633375232

## False Positives
Applications could use this notation occasionally which might generate some false positives. In that case Investigate the parent and child process.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "~1\" OR TgtProcImagePath containsCIS "~2\") AND (NOT (((SrcProcImagePath In Contains AnyCase ("C:\Windows\System32\Dism.exe","C:\Windows\System32\cleanmgr.exe")) OR (SrcProcImagePath endswithCIS "\WebEx\WebexHost.exe" OR SrcProcImagePath endswithCIS "\thor\thor64.exe") OR TgtProcDisplayName = "InstallShield (R)" OR TgtProcDisplayName = "InstallShield (R) Setup Engine" OR TgtProcPublisher = "InstallShield Software Corporation") OR ((TgtProcImagePath containsCIS "\AppData\" AND TgtProcImagePath containsCIS "\Temp\") OR (TgtProcImagePath endswithCIS "~1\unzip.exe" OR TgtProcImagePath endswithCIS "~1\7zG.exe"))))))

```