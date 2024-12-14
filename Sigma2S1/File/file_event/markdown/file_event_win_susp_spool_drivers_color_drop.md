# file_event_win_susp_spool_drivers_color_drop

## Title
Drop Binaries Into Spool Drivers Color Folder

## ID
ce7066a6-508a-42d3-995b-2952c65dc2ce

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-28

## Tags
attack.defense-evasion

## Description
Detects the creation of suspcious binary files inside the "\windows\system32\spool\drivers\color\" as seen in the blog referenced below

## References
https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".sys") AND TgtFilePath startswithCIS "C:\Windows\System32\spool\drivers\color\"))

```