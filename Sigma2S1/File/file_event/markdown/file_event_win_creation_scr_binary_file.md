# file_event_win_creation_scr_binary_file

## Title
Suspicious Screensaver Binary File Creation

## ID
97aa2e88-555c-450d-85a6-229bcd87efb8

## Author
frack113

## Date
2021-12-29

## Tags
attack.persistence, attack.t1546.002

## Description
Adversaries may establish persistence by executing malicious content triggered by user inactivity.
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".scr" AND (NOT ((SrcProcImagePath endswithCIS "\Kindle.exe" OR SrcProcImagePath endswithCIS "\Bin\ccSvcHst.exe") OR (SrcProcImagePath endswithCIS "\TiWorker.exe" AND TgtFilePath endswithCIS "\uwfservicingscr.scr")))))

```