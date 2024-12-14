# proc_creation_win_findstr_lnk

## Title
Findstr Launching .lnk File

## ID
33339be3-148b-4e16-af56-ad16ec6c7e7b

## Author
Trent Liffick

## Date
2020-05-01

## Tags
attack.defense-evasion, attack.t1036, attack.t1202, attack.t1027.003

## Description
Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack

## References
https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".lnk" OR TgtProcCmdLine endswithCIS ".lnk\"" OR TgtProcCmdLine endswithCIS ".lnk'") AND (TgtProcImagePath endswithCIS "\find.exe" OR TgtProcImagePath endswithCIS "\findstr.exe")))

```