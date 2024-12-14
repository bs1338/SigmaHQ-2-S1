# proc_creation_win_lolscript_register_app

## Title
Potential Register_App.Vbs LOLScript Abuse

## ID
28c8f68b-098d-45af-8d43-8089f3e35403

## Author
Austin Songer @austinsonger

## Date
2021-11-05

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects potential abuse of the "register_app.vbs" script that is part of the Windows SDK. The script offers the capability to register new VSS/VDS Provider as a COM+ application. Attackers can use this to install malicious DLLs for persistence and execution.

## References
https://twitter.com/sblmsrsn/status/1456613494783160325?s=20
https://github.com/microsoft/Windows-classic-samples/blob/7cbd99ac1d2b4a0beffbaba29ea63d024ceff700/Samples/Win7Samples/winbase/vss/vsssampleprovider/register_app.vbs

## False Positives
Other VB scripts that leverage the same starting command line flags

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ".vbs -register " AND (TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\wscript.exe")))

```