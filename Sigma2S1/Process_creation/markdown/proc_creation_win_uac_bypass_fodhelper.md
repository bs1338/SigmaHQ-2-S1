# proc_creation_win_uac_bypass_fodhelper

## Title
Bypass UAC via Fodhelper.exe

## ID
7f741dcf-fc22-4759-87b4-9ae8376676a2

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community

## Date
2019-10-24

## Tags
attack.privilege-escalation, attack.t1548.002

## Description
Identifies use of Fodhelper.exe to bypass User Account Control. Adversaries use this technique to execute privileged processes.

## References
https://eqllib.readthedocs.io/en/latest/analytics/e491ce22-792f-11e9-8f5c-d46d6d62a49e.html
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md

## False Positives
Legitimate use of fodhelper.exe utility by legitimate user

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\fodhelper.exe")

```