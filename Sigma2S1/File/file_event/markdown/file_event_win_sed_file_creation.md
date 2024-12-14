# file_event_win_sed_file_creation

## Title
Self Extraction Directive File Created In Potentially Suspicious Location

## ID
760e75d8-c3b5-409b-a9bf-6130b4c4603f

## Author
Joseliyo Sanchez, @Joseliyo_Jstnk

## Date
2024-02-05

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the creation of Self Extraction Directive files (.sed) in a potentially suspicious location.
These files are used by the "iexpress.exe" utility in order to create self extracting packages.
Attackers were seen abusing this utility and creating PE files with embedded ".sed" entries.


## References
https://strontic.github.io/xcyclopedia/library/iexpress.exe-D594B2A33EFAFD0EABF09E3FDC05FCEA.html
https://en.wikipedia.org/wiki/IExpress
https://www.virustotal.com/gui/file/602f4ae507fa8de57ada079adff25a6c2a899bd25cd092d0af7e62cdb619c93c/behavior

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS ":\ProgramData\" OR TgtFilePath containsCIS ":\Temp\" OR TgtFilePath containsCIS ":\Windows\System32\Tasks\" OR TgtFilePath containsCIS ":\Windows\Tasks\" OR TgtFilePath containsCIS ":\Windows\Temp\" OR TgtFilePath containsCIS "\AppData\Local\Temp\") AND TgtFilePath endswithCIS ".sed"))

```