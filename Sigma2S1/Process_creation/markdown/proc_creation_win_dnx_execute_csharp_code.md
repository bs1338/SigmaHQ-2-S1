# proc_creation_win_dnx_execute_csharp_code

## Title
Potential Application Whitelisting Bypass via Dnx.EXE

## ID
81ebd28b-9607-4478-bf06-974ed9d53ed7

## Author
Beyu Denis, oscd.community

## Date
2019-10-26

## Tags
attack.defense-evasion, attack.t1218, attack.t1027.004

## Description
Detects the execution of Dnx.EXE. The Dnx utility allows for the execution of C# code.
Attackers might abuse this in order to bypass application whitelisting.


## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Csi/
https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/

## False Positives
Legitimate use of dnx.exe by legitimate user

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\dnx.exe")

```