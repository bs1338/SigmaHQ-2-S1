# proc_creation_win_iexpress_susp_execution

## Title
Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location

## ID
b2b048b0-7857-4380-b0fb-d3f0ab820b71

## Author
Joseliyo Sanchez, @Joseliyo_Jstnk, Nasreddine Bencherchali (Nextron Systems)

## Date
2024-02-05

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the use of iexpress.exe to create binaries via Self Extraction Directive (SED) files located in potentially suspicious locations.
This behavior has been observed in-the-wild by different threat actors.


## References
https://strontic.github.io/xcyclopedia/library/iexpress.exe-D594B2A33EFAFD0EABF09E3FDC05FCEA.html
https://en.wikipedia.org/wiki/IExpress
https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/
https://www.virustotal.com/gui/file/602f4ae507fa8de57ada079adff25a6c2a899bd25cd092d0af7e62cdb619c93c/behavior

## False Positives
Administrators building packages using iexpress.exe

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -n " OR TgtProcCmdLine containsCIS " /n " OR TgtProcCmdLine containsCIS " â€“n " OR TgtProcCmdLine containsCIS " â€”n " OR TgtProcCmdLine containsCIS " â€•n ") AND TgtProcImagePath endswithCIS "\iexpress.exe" AND (TgtProcCmdLine containsCIS ":\ProgramData\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\System32\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\")))

```