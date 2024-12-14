# proc_creation_win_pua_cleanwipe

## Title
PUA - CleanWipe Execution

## ID
f44800ac-38ec-471f-936e-3fa7d9c53100

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2021-12-18

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.

## References
https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/CleanWipe

## False Positives
Legitimate administrative use (Should be investigated either way)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SepRemovalToolNative_x64.exe" OR (TgtProcCmdLine containsCIS "--uninstall" AND TgtProcImagePath endswithCIS "\CATClean.exe") OR (TgtProcCmdLine containsCIS "-r" AND TgtProcImagePath endswithCIS "\NetInstaller.exe") OR ((TgtProcCmdLine containsCIS "/uninstall" AND TgtProcCmdLine containsCIS "/enterprise") AND TgtProcImagePath endswithCIS "\WFPUnins.exe")))

```