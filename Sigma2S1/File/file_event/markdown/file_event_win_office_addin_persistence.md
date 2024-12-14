# file_event_win_office_addin_persistence

## Title
Potential Persistence Via Microsoft Office Add-In

## ID
8e1cb247-6cf6-42fa-b440-3f27d57e9936

## Author
NVISO

## Date
2020-05-11

## Tags
attack.persistence, attack.t1137.006

## Description
Detects potential persistence activity via startup add-ins that load when Microsoft Office starts (.wll/.xll are simply .dll fit for Word or Excel).

## References
Internal Research
https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence
https://github.com/redcanaryco/atomic-red-team/blob/4ae9580a1a8772db87a1b6cdb0d03e5af231e966/atomics/T1137.006/T1137.006.md

## False Positives
Legitimate add-ins

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\Microsoft\Addins\" AND (TgtFilePath endswithCIS ".xlam" OR TgtFilePath endswithCIS ".xla" OR TgtFilePath endswithCIS ".ppam")) OR (TgtFilePath containsCIS "\Microsoft\Word\Startup\" AND TgtFilePath endswithCIS ".wll") OR (TgtFilePath containsCIS "Microsoft\Excel\XLSTART\" AND TgtFilePath endswithCIS ".xlam") OR (TgtFilePath containsCIS "\Microsoft\Excel\Startup\" AND TgtFilePath endswithCIS ".xll")))

```