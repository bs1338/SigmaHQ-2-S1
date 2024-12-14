# proc_creation_win_certutil_encode_susp_location

## Title
File In Suspicious Location Encoded To Base64 Via Certutil.EXE

## ID
82a6714f-4899-4f16-9c1e-9a333544d4c3

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-15

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of certutil with the "encode" flag to encode a file to base64 where the files are located in potentially suspicious locations

## References
https://www.virustotal.com/gui/file/35c22725a92d5cb1016b09421c0a6cdbfd860fd4778b3313669b057d4a131cb7/behavior
https://www.virustotal.com/gui/file/427616528b7dbc4a6057ac89eb174a3a90f7abcf3f34e5a359b7a910d82f7a72/behavior
https://www.virustotal.com/gui/file/34de4c8beded481a4084a1fd77855c3e977e8ac643e5c5842d0f15f7f9b9086f/behavior
https://www.virustotal.com/gui/file/4abe1395a09fda06d897a9c4eb247278c1b6cddda5d126ce5b3f4f499e3b8fa2/behavior

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-encode" OR TgtProcCmdLine containsCIS "/encode" OR TgtProcCmdLine containsCIS "â€“encode" OR TgtProcCmdLine containsCIS "â€”encode" OR TgtProcCmdLine containsCIS "â€•encode") AND (TgtProcCmdLine containsCIS "\AppData\Roaming\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Local\Temp\" OR TgtProcCmdLine containsCIS "\PerfLogs\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\Windows\Temp\" OR TgtProcCmdLine containsCIS "$Recycle.Bin") AND TgtProcImagePath endswithCIS "\certutil.exe"))

```