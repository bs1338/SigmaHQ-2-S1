# proc_creation_win_hktl_pypykatz

## Title
HackTool - Pypykatz Credentials Dumping Activity

## ID
a29808fd-ef50-49ff-9c7a-59a9b040b404

## Author
frack113

## Date
2022-01-05

## Tags
attack.credential-access, attack.t1003.002

## Description
Detects the usage of "pypykatz" to obtain stored credentials. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database through Windows registry where the SAM database is stored

## References
https://github.com/skelsec/pypykatz
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-2---registry-parse-with-pypykatz

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "live" AND TgtProcCmdLine containsCIS "registry") AND (TgtProcImagePath endswithCIS "\pypykatz.exe" OR TgtProcImagePath endswithCIS "\python.exe")))

```