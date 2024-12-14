# proc_creation_win_wlrmdr_uncommon_child_process

## Title
Wlrmdr.EXE Uncommon Argument Or Child Process

## ID
9cfc00b6-bfb7-49ce-9781-ef78503154bb

## Author
frack113, manasmbellani

## Date
2022-02-16

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the execution of "Wlrmdr.exe" with the "-u" command line flag which allows anything passed to it to be an argument of the ShellExecute API, which would allow an attacker to execute arbitrary binaries.
This detection also focuses on any uncommon child processes spawned from "Wlrmdr.exe" as a supplement for those that posses "ParentImage" telemetry.


## References
https://twitter.com/0gtweet/status/1493963591745220608?s=20&t=xUg9DsZhJy1q9bPTUWgeIQ
https://lolbas-project.github.io/lolbas/Binaries/Wlrmdr/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\wlrmdr.exe" OR ((((TgtProcCmdLine containsCIS "-s " OR TgtProcCmdLine containsCIS "/s " OR TgtProcCmdLine containsCIS "â€“s " OR TgtProcCmdLine containsCIS "â€”s " OR TgtProcCmdLine containsCIS "â€•s ") AND (TgtProcCmdLine containsCIS "-f " OR TgtProcCmdLine containsCIS "/f " OR TgtProcCmdLine containsCIS "â€“f " OR TgtProcCmdLine containsCIS "â€”f " OR TgtProcCmdLine containsCIS "â€•f ") AND (TgtProcCmdLine containsCIS "-t " OR TgtProcCmdLine containsCIS "/t " OR TgtProcCmdLine containsCIS "â€“t " OR TgtProcCmdLine containsCIS "â€”t " OR TgtProcCmdLine containsCIS "â€•t ") AND (TgtProcCmdLine containsCIS "-m " OR TgtProcCmdLine containsCIS "/m " OR TgtProcCmdLine containsCIS "â€“m " OR TgtProcCmdLine containsCIS "â€”m " OR TgtProcCmdLine containsCIS "â€•m ") AND (TgtProcCmdLine containsCIS "-a " OR TgtProcCmdLine containsCIS "/a " OR TgtProcCmdLine containsCIS "â€“a " OR TgtProcCmdLine containsCIS "â€”a " OR TgtProcCmdLine containsCIS "â€•a ") AND (TgtProcCmdLine containsCIS "-u " OR TgtProcCmdLine containsCIS "/u " OR TgtProcCmdLine containsCIS "â€“u " OR TgtProcCmdLine containsCIS "â€”u " OR TgtProcCmdLine containsCIS "â€•u ")) AND TgtProcImagePath endswithCIS "\wlrmdr.exe") AND (NOT ((SrcProcImagePath In Contains AnyCase ("","-")) OR SrcProcImagePath IS NOT EMPTY OR SrcProcImagePath = "C:\Windows\System32\winlogon.exe")))))

```