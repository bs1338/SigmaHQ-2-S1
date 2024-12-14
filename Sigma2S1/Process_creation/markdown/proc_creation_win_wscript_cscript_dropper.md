# proc_creation_win_wscript_cscript_dropper

## Title
Potential Dropper Script Execution Via WScript/CScript

## ID
cea72823-df4d-4567-950c-0b579eaf0846

## Author
Margaritis Dimitrios (idea), Florian Roth (Nextron Systems), oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-01-16

## Tags
attack.execution, attack.t1059.005, attack.t1059.007

## Description
Detects wscript/cscript executions of scripts located in user directories

## References
https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
https://redcanary.com/blog/gootloader/

## False Positives
Some installers might generate a similar behavior. An initial baseline is required

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe") AND (TgtProcCmdLine containsCIS ".js" OR TgtProcCmdLine containsCIS ".jse" OR TgtProcCmdLine containsCIS ".vba" OR TgtProcCmdLine containsCIS ".vbe" OR TgtProcCmdLine containsCIS ".vbs" OR TgtProcCmdLine containsCIS ".wsf") AND (TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Tmp\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\")))

```