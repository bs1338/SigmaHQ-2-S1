# proc_creation_win_curl_insecure_porxy_or_doh

## Title
Insecure Proxy/DOH Transfer Via Curl.EXE

## ID
2c1486f5-02e8-4f86-9099-b97f2da4ed77

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-27

## Tags
attack.execution

## Description
Detects execution of "curl.exe" with the "insecure" flag over proxy or DOH.

## References
https://curl.se/docs/manpage.html

## False Positives
Access to badly maintained internal or development systems

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "--doh-insecure" OR TgtProcCmdLine containsCIS "--proxy-insecure") AND TgtProcImagePath endswithCIS "\curl.exe"))

```