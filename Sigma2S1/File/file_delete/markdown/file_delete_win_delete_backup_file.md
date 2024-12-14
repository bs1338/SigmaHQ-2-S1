# file_delete_win_delete_backup_file

## Title
Backup Files Deleted

## ID
06125661-3814-4e03-bfa2-1e4411c60ac3

## Author
frack113

## Date
2022-01-02

## Tags
attack.impact, attack.t1490

## Description
Detects deletion of files with extensions often used for backup files. Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-6---windows---delete-backup-files

## False Positives
Legitime usage

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\wt.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe") AND (TgtFilePath endswithCIS ".VHD" OR TgtFilePath endswithCIS ".bac" OR TgtFilePath endswithCIS ".bak" OR TgtFilePath endswithCIS ".wbcat" OR TgtFilePath endswithCIS ".bkf" OR TgtFilePath endswithCIS ".set" OR TgtFilePath endswithCIS ".win" OR TgtFilePath endswithCIS ".dsk")))

```