# proc_creation_win_wab_execution_from_non_default_location

## Title
Wab Execution From Non Default Location

## ID
395907ee-96e5-4666-af2e-2ca91688e151

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-12

## Tags
attack.defense-evasion, attack.execution

## Description
Detects execution of wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) from non default locations as seen with bumblebee activity

## References
https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bumblebee-loader-cybercrime
https://thedfirreport.com/2022/09/26/bumblebee-round-two/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\wab.exe" OR TgtProcImagePath endswithCIS "\wabmig.exe") AND (NOT (TgtProcImagePath startswithCIS "C:\Windows\WinSxS\" OR TgtProcImagePath startswithCIS "C:\Program Files\Windows Mail\" OR TgtProcImagePath startswithCIS "C:\Program Files (x86)\Windows Mail\"))))

```