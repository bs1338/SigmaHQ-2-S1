# proc_creation_win_susp_recon

## Title
Recon Information for Export with Command Prompt

## ID
aa2efee7-34dd-446e-8a37-40790a66efd7

## Author
frack113

## Date
2021-07-30

## Tags
attack.collection, attack.t1119

## Description
Once established within a system or network, an adversary may use automated techniques for collecting internal data.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\tree.com" OR TgtProcImagePath endswithCIS "\WMIC.exe" OR TgtProcImagePath endswithCIS "\doskey.exe" OR TgtProcImagePath endswithCIS "\sc.exe") AND (SrcProcCmdLine containsCIS " > %TEMP%\" OR SrcProcCmdLine containsCIS " > %TMP%\")))

```