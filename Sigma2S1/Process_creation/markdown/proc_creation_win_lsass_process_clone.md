# proc_creation_win_lsass_process_clone

## Title
Potential Credential Dumping Via LSASS Process Clone

## ID
c8da0dfd-4ed0-4b68-962d-13c9c884384e

## Author
Florian Roth (Nextron Systems), Samir Bousseaden

## Date
2021-11-27

## Tags
attack.credential-access, attack.t1003, attack.t1003.001

## Description
Detects a suspicious LSASS process process clone that could be a sign of credential dumping activity

## References
https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
https://twitter.com/Hexacorn/status/1420053502554951689
https://twitter.com/SBousseaden/status/1464566846594691073?s=20

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\Windows\System32\lsass.exe" AND SrcProcImagePath endswithCIS "\Windows\System32\lsass.exe"))

```