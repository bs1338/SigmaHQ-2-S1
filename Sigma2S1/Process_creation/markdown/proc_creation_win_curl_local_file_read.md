# proc_creation_win_curl_local_file_read

## Title
Local File Read Using Curl.EXE

## ID
aa6f6ea6-0676-40dd-b510-6e46f02d8867

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-27

## Tags
attack.execution

## Description
Detects execution of "curl.exe" with the "file://" protocol handler in order to read local files.

## References
https://curl.se/docs/manpage.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "file:///" AND TgtProcImagePath endswithCIS "\curl.exe"))

```