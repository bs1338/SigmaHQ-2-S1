# proc_creation_win_office_excel_dcom_lateral_movement

## Title
Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp

## ID
551d9c1f-816c-445b-a7a6-7a3864720d60

## Author
Aaron Stratton

## Date
2023-11-13

## Tags
attack.t1021.003, attack.lateral-movement

## Description
Detects suspicious child processes of Excel which could be an indicator of lateral movement leveraging the "ActivateMicrosoftApp" Excel DCOM object.


## References
https://posts.specterops.io/lateral-movement-abuse-the-power-of-dcom-excel-application-3c016d0d9922
https://github.com/grayhatkiller/SharpExShell
https://learn.microsoft.com/en-us/office/vba/api/excel.xlmsapplication

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\foxprow.exe" OR TgtProcImagePath endswithCIS "\schdplus.exe" OR TgtProcImagePath endswithCIS "\winproj.exe") AND SrcProcImagePath endswithCIS "\excel.exe"))

```