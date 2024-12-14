# proc_creation_win_cipher_overwrite_deleted_data

## Title
Deleted Data Overwritten Via Cipher.EXE

## ID
4b046706-5789-4673-b111-66f25fe99534

## Author
frack113

## Date
2021-12-26

## Tags
attack.impact, attack.t1485

## Description
Detects usage of the "cipher" built-in utility in order to overwrite deleted data from disk.
Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.
Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md#atomic-test-3---overwrite-deleted-data-on-c-drive

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " /w:" AND TgtProcImagePath endswithCIS "\cipher.exe"))

```