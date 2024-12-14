# proc_creation_win_susp_alternate_data_streams

## Title
Execute From Alternate Data Streams

## ID
7f43c430-5001-4f8b-aaa9-c3b88f18fa5c

## Author
frack113

## Date
2021-09-01

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "txt:" AND ((TgtProcCmdLine containsCIS "esentutl " AND TgtProcCmdLine containsCIS " /y " AND TgtProcCmdLine containsCIS " /d " AND TgtProcCmdLine containsCIS " /o ") OR (TgtProcCmdLine containsCIS "makecab " AND TgtProcCmdLine containsCIS ".cab") OR (TgtProcCmdLine containsCIS "reg " AND TgtProcCmdLine containsCIS " export ") OR (TgtProcCmdLine containsCIS "regedit " AND TgtProcCmdLine containsCIS " /E ") OR (TgtProcCmdLine containsCIS "type " AND TgtProcCmdLine containsCIS " > "))))

```