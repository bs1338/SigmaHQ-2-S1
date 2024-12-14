# proc_creation_win_clip_execution

## Title
Data Copied To Clipboard Via Clip.EXE

## ID
ddeff553-5233-4ae9-bbab-d64d2bd634be

## Author
frack113

## Date
2021-07-27

## Tags
attack.collection, attack.t1115

## Description
Detects the execution of clip.exe in order to copy data to the clipboard. Adversaries may collect data stored in the clipboard from users copying information within or between applications.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/clip
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1115/T1115.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\clip.exe")

```