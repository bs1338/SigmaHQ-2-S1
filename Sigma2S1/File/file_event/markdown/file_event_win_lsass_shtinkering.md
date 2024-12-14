# file_event_win_lsass_shtinkering

## Title
LSASS Process Dump Artefact In CrashDumps Folder

## ID
6902955a-01b7-432c-b32a-6f5f81d8f625

## Author
@pbssubhash

## Date
2022-12-08

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the presence of an LSASS dump file in the "CrashDumps" folder. This could be a sign of LSASS credential dumping. Techniques such as the LSASS Shtinkering have been seen abusing the Windows Error Reporting to dump said process.

## References
https://github.com/deepinstinct/Lsass-Shtinkering
https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf

## False Positives
Rare legitimate dump of the process by the operating system due to a crash of lsass

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "lsass.exe." AND TgtFilePath endswithCIS ".dmp" AND TgtFilePath startswithCIS "C:\Windows\System32\config\systemprofile\AppData\Local\CrashDumps\"))

```