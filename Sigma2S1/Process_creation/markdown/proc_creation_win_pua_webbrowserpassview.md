# proc_creation_win_pua_webbrowserpassview

## Title
PUA - WebBrowserPassView Execution

## ID
d0dae994-26c6-4d2d-83b5-b3c8b79ae513

## Author
frack113

## Date
2022-08-20

## Tags
attack.credential-access, attack.t1555.003

## Description
Detects the execution of WebBrowserPassView.exe. A password recovery tool that reveals the passwords stored by the following Web browsers, Internet Explorer (Version 4.0 - 11.0), Mozilla Firefox (All Versions), Google Chrome, Safari, and Opera

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1555.003/T1555.003.md

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName = "Web Browser Password Viewer" OR TgtProcImagePath endswithCIS "\WebBrowserPassView.exe"))

```