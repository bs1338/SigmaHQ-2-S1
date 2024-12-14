# file_event_win_hktl_nppspy

## Title
HackTool - NPPSpy Hacktool Usage

## ID
cad1fe90-2406-44dc-bd03-59d0b58fe722

## Author
Florian Roth (Nextron Systems)

## Date
2021-11-29

## Tags
attack.credential-access

## Description
Detects the use of NPPSpy hacktool that stores cleartext passwords of users that logged in to a local file

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003/T1003.md#atomic-test-2---credential-dumping-with-nppspy
https://twitter.com/0gtweet/status/1465282548494487554

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\NPPSpy.txt" OR TgtFilePath endswithCIS "\NPPSpy.dll"))

```