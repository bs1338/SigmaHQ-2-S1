# file_event_win_ntds_dit_uncommon_process

## Title
NTDS.DIT Creation By Uncommon Process

## ID
11b1ed55-154d-4e82-8ad7-83739298f720

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-11

## Tags
attack.credential-access, attack.t1003.002, attack.t1003.003

## Description
Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon process or a process located in a suspicious directory

## References
https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/
https://adsecurity.org/?p=2398

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\ntds.dit" AND ((SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\wsl.exe" OR SrcProcImagePath endswithCIS "\wt.exe") OR (SrcProcImagePath containsCIS "\AppData\" OR SrcProcImagePath containsCIS "\Temp\" OR SrcProcImagePath containsCIS "\Public\" OR SrcProcImagePath containsCIS "\PerfLogs\"))))

```