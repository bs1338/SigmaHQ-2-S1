# file_event_win_install_teamviewer_desktop

## Title
Installation of TeamViewer Desktop

## ID
9711de76-5d4f-4c50-a94f-21e4e8f8384d

## Author
frack113

## Date
2022-01-28

## Tags
attack.command-and-control, attack.t1219

## Description
TeamViewer_Desktop.exe is create during install

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-1---teamviewer-files-detected-test-on-windows

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\TeamViewer_Desktop.exe")

```