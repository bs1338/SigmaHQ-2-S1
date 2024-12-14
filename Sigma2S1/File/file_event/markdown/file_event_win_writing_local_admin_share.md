# file_event_win_writing_local_admin_share

## Title
Writing Local Admin Share

## ID
4aafb0fa-bff5-4b9d-b99e-8093e659c65f

## Author
frack113

## Date
2022-01-01

## Tags
attack.lateral-movement, attack.t1546.002

## Description
Aversaries may use to interact with a remote network share using Server Message Block (SMB).
This technique is used by post-exploitation frameworks.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.002/T1021.002.md#atomic-test-4---execute-command-writing-output-to-local-admin-share

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "\\127.0.0" AND TgtFilePath containsCIS "\ADMIN$\"))

```