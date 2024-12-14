# proc_creation_win_certutil_encode_susp_extensions

## Title
Suspicious File Encoded To Base64 Via Certutil.EXE

## ID
ea0cdc3e-2239-4f26-a947-4e8f8224e464

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-15

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of certutil with the "encode" flag to encode a file to base64 where the extensions of the file is suspicious

## References
https://www.virustotal.com/gui/file/35c22725a92d5cb1016b09421c0a6cdbfd860fd4778b3313669b057d4a131cb7/behavior
https://www.virustotal.com/gui/file/427616528b7dbc4a6057ac89eb174a3a90f7abcf3f34e5a359b7a910d82f7a72/behavior
https://www.virustotal.com/gui/file/34de4c8beded481a4084a1fd77855c3e977e8ac643e5c5842d0f15f7f9b9086f/behavior
https://www.virustotal.com/gui/file/4abe1395a09fda06d897a9c4eb247278c1b6cddda5d126ce5b3f4f499e3b8fa2/behavior

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-encode" OR TgtProcCmdLine containsCIS "/encode" OR TgtProcCmdLine containsCIS "â€“encode" OR TgtProcCmdLine containsCIS "â€”encode" OR TgtProcCmdLine containsCIS "â€•encode") AND (TgtProcCmdLine containsCIS ".acl" OR TgtProcCmdLine containsCIS ".bat" OR TgtProcCmdLine containsCIS ".doc" OR TgtProcCmdLine containsCIS ".gif" OR TgtProcCmdLine containsCIS ".jpeg" OR TgtProcCmdLine containsCIS ".jpg" OR TgtProcCmdLine containsCIS ".mp3" OR TgtProcCmdLine containsCIS ".pdf" OR TgtProcCmdLine containsCIS ".png" OR TgtProcCmdLine containsCIS ".ppt" OR TgtProcCmdLine containsCIS ".tmp" OR TgtProcCmdLine containsCIS ".xls" OR TgtProcCmdLine containsCIS ".xml") AND TgtProcImagePath endswithCIS "\certutil.exe"))

```