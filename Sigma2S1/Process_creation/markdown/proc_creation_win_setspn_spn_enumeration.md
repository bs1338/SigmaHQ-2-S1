# proc_creation_win_setspn_spn_enumeration

## Title
Potential SPN Enumeration Via Setspn.EXE

## ID
1eeed653-dbc8-4187-ad0c-eeebb20e6599

## Author
Markus Neis, keepwatch

## Date
2018-11-14

## Tags
attack.credential-access, attack.t1558.003

## Description
Detects service principal name (SPN) enumeration used for Kerberoasting

## References
https://web.archive.org/web/20200329173843/https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
https://www.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation/?edition=2019

## False Positives
Administration activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -q " OR TgtProcCmdLine containsCIS " /q ") AND (TgtProcImagePath endswithCIS "\setspn.exe" OR (TgtProcDisplayName containsCIS "Query or reset the computer" AND TgtProcDisplayName containsCIS "SPN attribute"))))

```