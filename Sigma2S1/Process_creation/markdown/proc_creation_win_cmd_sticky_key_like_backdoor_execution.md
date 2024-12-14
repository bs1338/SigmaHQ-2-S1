# proc_creation_win_cmd_sticky_key_like_backdoor_execution

## Title
Sticky Key Like Backdoor Execution

## ID
2fdefcb3-dbda-401e-ae23-f0db027628bc

## Author
Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community

## Date
2018-03-15

## Tags
attack.privilege-escalation, attack.persistence, attack.t1546.008, car.2014-11-003, car.2014-11-008

## Description
Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen

## References
https://learn.microsoft.com/en-us/archive/blogs/jonathantrull/detecting-sticky-key-backdoors

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "sethc.exe" OR TgtProcCmdLine containsCIS "utilman.exe" OR TgtProcCmdLine containsCIS "osk.exe" OR TgtProcCmdLine containsCIS "Magnify.exe" OR TgtProcCmdLine containsCIS "Narrator.exe" OR TgtProcCmdLine containsCIS "DisplaySwitch.exe") AND (TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\wt.exe") AND SrcProcImagePath endswithCIS "\winlogon.exe"))

```