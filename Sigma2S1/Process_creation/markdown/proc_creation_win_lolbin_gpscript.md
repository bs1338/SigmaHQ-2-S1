# proc_creation_win_lolbin_gpscript

## Title
Gpscript Execution

## ID
1e59c230-6670-45bf-83b0-98903780607e

## Author
frack113

## Date
2022-05-16

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the execution of the LOLBIN gpscript, which executes logon or startup scripts configured in Group Policy

## References
https://oddvar.moe/2018/04/27/gpscript-exe-another-lolbin-to-the-list/
https://lolbas-project.github.io/lolbas/Binaries/Gpscript/

## False Positives
Legitimate uses of logon scripts distributed via group policy

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " /logon" OR TgtProcCmdLine containsCIS " /startup") AND TgtProcImagePath endswithCIS "\gpscript.exe") AND (NOT SrcProcCmdLine = "C:\windows\system32\svchost.exe -k netsvcs -p -s gpsvc")))

```