# proc_creation_win_hktl_safetykatz

## Title
HackTool - SafetyKatz Execution

## ID
b1876533-4ed5-4a83-90f3-b8645840a413

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-20

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects the execution of the hacktool SafetyKatz via PE information and default Image name

## References
https://github.com/GhostPack/SafetyKatz

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SafetyKatz.exe" OR TgtProcDisplayName = "SafetyKatz"))

```