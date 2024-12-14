# proc_creation_win_lolbin_msdeploy

## Title
Execute Files with Msdeploy.exe

## ID
646bc99f-6682-4b47-a73a-17b1b64c9d34

## Author
Beyu Denis, oscd.community

## Date
2020-10-18

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects file execution using the msdeploy.exe lolbin

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msdeploy/
https://twitter.com/pabraeken/status/995837734379032576
https://twitter.com/pabraeken/status/999090532839313408

## False Positives
System administrator Usage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "verb:sync" AND TgtProcCmdLine containsCIS "-source:RunCommand" AND TgtProcCmdLine containsCIS "-dest:runCommand") AND TgtProcImagePath endswithCIS "\msdeploy.exe"))

```