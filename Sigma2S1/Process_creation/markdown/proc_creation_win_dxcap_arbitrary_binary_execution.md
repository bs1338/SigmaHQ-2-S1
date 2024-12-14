# proc_creation_win_dxcap_arbitrary_binary_execution

## Title
New Capture Session Launched Via DXCap.EXE

## ID
60f16a96-db70-42eb-8f76-16763e333590

## Author
Beyu Denis, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-10-26

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the execution of "DXCap.EXE" with the "-c" flag, which allows a user to launch any arbitrary binary or windows package through DXCap itself. This can be abused to potentially bypass application whitelisting.


## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Dxcap/
https://twitter.com/harr0ey/status/992008180904419328

## False Positives
Legitimate execution of dxcap.exe by legitimate user

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -c " AND TgtProcImagePath endswithCIS "\DXCap.exe"))

```