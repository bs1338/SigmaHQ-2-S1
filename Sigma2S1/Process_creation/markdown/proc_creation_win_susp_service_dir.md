# proc_creation_win_susp_service_dir

## Title
Suspicious Service Binary Directory

## ID
883faa95-175a-4e22-8181-e5761aeb373c

## Author
Florian Roth (Nextron Systems)

## Date
2021-03-09

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects a service binary running in a suspicious directory

## References
https://blog.truesec.com/2021/03/07/exchange-zero-day-proxylogon-and-hafnium/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "\Users\Public\" OR TgtProcImagePath containsCIS "\$Recycle.bin" OR TgtProcImagePath containsCIS "\Users\All Users\" OR TgtProcImagePath containsCIS "\Users\Default\" OR TgtProcImagePath containsCIS "\Users\Contacts\" OR TgtProcImagePath containsCIS "\Users\Searches\" OR TgtProcImagePath containsCIS "C:\Perflogs\" OR TgtProcImagePath containsCIS "\config\systemprofile\" OR TgtProcImagePath containsCIS "\Windows\Fonts\" OR TgtProcImagePath containsCIS "\Windows\IME\" OR TgtProcImagePath containsCIS "\Windows\addins\") AND (SrcProcImagePath endswithCIS "\services.exe" OR SrcProcImagePath endswithCIS "\svchost.exe")))

```