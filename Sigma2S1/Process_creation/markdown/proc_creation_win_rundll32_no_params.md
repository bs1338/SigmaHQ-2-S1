# proc_creation_win_rundll32_no_params

## Title
Rundll32 Execution Without CommandLine Parameters

## ID
1775e15e-b61b-4d14-a1a3-80981298085a

## Author
Florian Roth (Nextron Systems)

## Date
2021-05-27

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity

## References
https://www.cobaltstrike.com/help-opsec
https://twitter.com/ber_m1ng/status/1397948048135778309

## False Positives
Possible but rare

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS "\rundll32.exe" OR TgtProcCmdLine endswithCIS "\rundll32.exe\"" OR TgtProcCmdLine endswithCIS "\rundll32") AND (NOT (SrcProcImagePath containsCIS "\AppData\Local\" OR SrcProcImagePath containsCIS "\Microsoft\Edge\"))))

```