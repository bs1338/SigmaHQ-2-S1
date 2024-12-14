# file_event_win_new_scr_file

## Title
SCR File Write Event

## ID
c048f047-7e2a-4888-b302-55f509d4a91d

## Author
Christopher Peacock @securepeacock, SCYTHE @scythe_io

## Date
2022-04-27

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects the creation of screensaver files (.scr) outside of system folders. Attackers may execute an application as an ".SCR" file using "rundll32.exe desk.cpl,InstallScreenSaver" for example.

## References
https://lolbas-project.github.io/lolbas/Libraries/Desk/

## False Positives
The installation of new screen savers by third party software

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".scr" AND (NOT (TgtFilePath containsCIS ":\$WINDOWS.~BT\NewOS\" OR TgtFilePath containsCIS ":\Windows\System32\" OR TgtFilePath containsCIS ":\Windows\SysWOW64\" OR TgtFilePath containsCIS ":\Windows\WinSxS\" OR TgtFilePath containsCIS ":\WUDownloadCache\"))))

```