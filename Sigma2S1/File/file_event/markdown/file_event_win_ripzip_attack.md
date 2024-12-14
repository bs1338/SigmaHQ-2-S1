# file_event_win_ripzip_attack

## Title
Potential RipZip Attack on Startup Folder

## ID
a6976974-ea6f-4e97-818e-ea08625c52cb

## Author
Greg (rule)

## Date
2022-07-21

## Tags
attack.persistence, attack.t1547

## Description
Detects a phishing attack which expands a ZIP file containing a malicious shortcut.
If the victim expands the ZIP file via the explorer process, then the explorer process expands the malicious ZIP file and drops a malicious shortcut redirected to a backdoor into the Startup folder.
Additionally, the file name of the malicious shortcut in Startup folder contains {0AFACED1-E828-11D1-9187-B532F1E9575D} meaning the folder shortcut operation.


## References
https://twitter.com/jonasLyk/status/1549338335243534336?t=CrmPocBGLbDyE4p6zTX1cg&s=19

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\explorer.exe" AND (TgtFilePath containsCIS "\Microsoft\Windows\Start Menu\Programs\Startup" AND TgtFilePath containsCIS ".lnk.{0AFACED1-E828-11D1-9187-B532F1E9575D}")))

```