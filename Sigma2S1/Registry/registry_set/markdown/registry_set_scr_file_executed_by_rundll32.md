# registry_set_scr_file_executed_by_rundll32

## Title
ScreenSaver Registry Key Set

## ID
40b6e656-4e11-4c0c-8772-c1cc6dae34ce

## Author
Jose Luis Sanchez Martinez (@Joseliyo_Jstnk)

## Date
2022-05-04

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects registry key established after masqueraded .scr file execution using Rundll32 through desk.cpl

## References
https://twitter.com/VakninHai/status/1517027824984547329
https://twitter.com/pabraeken/status/998627081360695297
https://jstnk9.github.io/jstnk9/research/InstallScreenSaver-SCR-files

## False Positives
Legitimate use of screen saver

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\rundll32.exe" AND (RegistryValue endswithCIS ".scr" AND RegistryKeyPath containsCIS "\Control Panel\Desktop\SCRNSAVE.EXE") AND (NOT (RegistryValue containsCIS "C:\Windows\System32\" OR RegistryValue containsCIS "C:\Windows\SysWOW64\"))))

```