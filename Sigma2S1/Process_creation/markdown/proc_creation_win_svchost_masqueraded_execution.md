# proc_creation_win_svchost_masqueraded_execution

## Title
Suspicious Process Masquerading As SvcHost.EXE

## ID
be58d2e2-06c8-4f58-b666-b99f6dc3b6cd

## Author
Swachchhanda Shrawan Poudel

## Date
2024-08-07

## Tags
attack.defense-evasion, attack.t1036.005

## Description
Detects a suspicious process that is masquerading as the legitimate "svchost.exe" by naming its binary "svchost.exe" and executing from an uncommon location.
Adversaries often disguise their malicious binaries by naming them after legitimate system processes like "svchost.exe" to evade detection.


## References
https://tria.ge/240731-jh4crsycnb/behavioral2
https://redcanary.com/blog/threat-detection/process-masquerading/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\svchost.exe" AND (NOT (TgtProcImagePath In Contains AnyCase ("C:\Windows\System32\svchost.exe","C:\Windows\SysWOW64\svchost.exe")))))

```