# proc_creation_win_curl_cookie_hijacking

## Title
Potential Cookies Session Hijacking

## ID
5a6e1e16-07de-48d8-8aae-faa766c05e88

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-27

## Tags
attack.execution

## Description
Detects execution of "curl.exe" with the "-c" flag in order to save cookie data.

## References
https://curl.se/docs/manpage.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine RegExp "\\s-c\\s" OR TgtProcCmdLine containsCIS "--cookie-jar") AND TgtProcImagePath endswithCIS "\curl.exe"))

```