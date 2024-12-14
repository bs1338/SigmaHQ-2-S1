# proc_creation_win_mshta_lethalhta_technique

## Title
Potential LethalHTA Technique Execution

## ID
ed5d72a6-f8f4-479d-ba79-02f6a80d7471

## Author
Markus Neis

## Date
2018-06-07

## Tags
attack.defense-evasion, attack.t1218.005

## Description
Detects potential LethalHTA technique where the "mshta.exe" is spawned by an "svchost.exe" process

## References
https://codewhitesec.blogspot.com/2018/07/lethalhta.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\mshta.exe" AND SrcProcImagePath endswithCIS "\svchost.exe"))

```