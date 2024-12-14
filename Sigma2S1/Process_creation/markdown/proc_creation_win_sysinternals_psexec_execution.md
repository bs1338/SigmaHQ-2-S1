# proc_creation_win_sysinternals_psexec_execution

## Title
Psexec Execution

## ID
730fc21b-eaff-474b-ad23-90fd265d4988

## Author
omkar72

## Date
2020-10-30

## Tags
attack.execution, attack.t1569, attack.t1021

## Description
Detects user accept agreement execution in psexec commandline

## References
https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html

## False Positives
Administrative scripts.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\psexec.exe")

```