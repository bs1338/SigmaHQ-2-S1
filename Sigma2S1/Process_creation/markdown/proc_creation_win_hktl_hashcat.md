# proc_creation_win_hktl_hashcat

## Title
HackTool - Hashcat Password Cracker Execution

## ID
39b31e81-5f5f-4898-9c0e-2160cfc0f9bf

## Author
frack113

## Date
2021-12-27

## Tags
attack.credential-access, attack.t1110.002

## Description
Execute Hashcat.exe with provided SAM file from registry of Windows and Password list to crack against

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1110.002/T1110.002.md#atomic-test-1---password-cracking-with-hashcat
https://hashcat.net/wiki/doku.php?id=hashcat

## False Positives
Tools that use similar command line flags and values

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-a " AND TgtProcCmdLine containsCIS "-m 1000 " AND TgtProcCmdLine containsCIS "-r ") OR TgtProcImagePath endswithCIS "\hashcat.exe"))

```