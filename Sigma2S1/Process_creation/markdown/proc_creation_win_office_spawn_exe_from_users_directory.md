# proc_creation_win_office_spawn_exe_from_users_directory

## Title
Suspicious Binary In User Directory Spawned From Office Application

## ID
aa3a6f94-890e-4e22-b634-ffdfd54792cc

## Author
Jason Lynch

## Date
2019-04-02

## Tags
attack.execution, attack.t1204.002, attack.g0046, car.2013-05-002

## Description
Detects an executable in the users directory started from one of the Microsoft Office suite applications (Word, Excel, PowerPoint, Publisher, Visio)

## References
https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign
https://www.virustotal.com/gui/file/23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS ".exe" AND TgtProcImagePath startswithCIS "C:\users\" AND (SrcProcImagePath endswithCIS "\WINWORD.EXE" OR SrcProcImagePath endswithCIS "\EXCEL.EXE" OR SrcProcImagePath endswithCIS "\POWERPNT.exe" OR SrcProcImagePath endswithCIS "\MSPUB.exe" OR SrcProcImagePath endswithCIS "\VISIO.exe" OR SrcProcImagePath endswithCIS "\MSACCESS.exe" OR SrcProcImagePath endswithCIS "\EQNEDT32.exe")) AND (NOT TgtProcImagePath endswithCIS "\Teams.exe")))

```