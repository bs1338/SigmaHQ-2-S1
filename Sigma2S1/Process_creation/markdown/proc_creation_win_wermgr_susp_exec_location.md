# proc_creation_win_wermgr_susp_exec_location

## Title
Suspicious Execution Location Of Wermgr.EXE

## ID
5394fcc7-aeb2-43b5-9a09-cac9fc5edcd5

## Author
Florian Roth (Nextron Systems)

## Date
2022-10-14

## Tags
attack.execution

## Description
Detects suspicious Windows Error Reporting manager (wermgr.exe) execution location.

## References
https://www.trendmicro.com/en_us/research/22/j/black-basta-infiltrates-networks-via-qakbot-brute-ratel-and-coba.html
https://www.echotrail.io/insights/search/wermgr.exe
https://github.com/binderlabs/DirCreate2System

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\wermgr.exe" AND (NOT (TgtProcImagePath startswithCIS "C:\Windows\System32\" OR TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\" OR TgtProcImagePath startswithCIS "C:\Windows\WinSxS\"))))

```