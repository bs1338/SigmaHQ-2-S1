# file_event_win_anydesk_writing_susp_binaries

## Title
Suspicious Binary Writes Via AnyDesk

## ID
2d367498-5112-4ae5-a06a-96e7bc33a211

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-28

## Tags
attack.command-and-control, attack.t1219

## Description
Detects AnyDesk writing binary files to disk other than "gcapi.dll".
According to RedCanary research it is highly abnormal for AnyDesk to write executable files to disk besides gcapi.dll,
which is a legitimate DLL that is part of the Google Chrome web browser used to interact with the Google Cloud API. (See reference section for more details)


## References
https://redcanary.com/blog/misbehaving-rats/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\anydesk.exe" AND (TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe")) AND (NOT TgtFilePath endswithCIS "\gcapi.dll")))

```