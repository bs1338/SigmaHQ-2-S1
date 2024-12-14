# file_event_win_creation_unquoted_service_path

## Title
Creation Exe for Service with Unquoted Path

## ID
8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9

## Author
frack113

## Date
2021-12-30

## Tags
attack.persistence, attack.t1547.009

## Description
Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.009/T1574.009.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath = "C:\program.exe")

```