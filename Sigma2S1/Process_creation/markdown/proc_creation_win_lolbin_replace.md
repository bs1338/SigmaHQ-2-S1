# proc_creation_win_lolbin_replace

## Title
Replace.exe Usage

## ID
9292293b-8496-4715-9db6-37028dcda4b3

## Author
frack113

## Date
2022-03-06

## Tags
attack.command-and-control, attack.t1105

## Description
Detects the use of Replace.exe which can be used to replace file with another file

## References
https://lolbas-project.github.io/lolbas/Binaries/Replace/
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/replace

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\replace.exe" AND (TgtProcCmdLine containsCIS "-a" OR TgtProcCmdLine containsCIS "/a" OR TgtProcCmdLine containsCIS "â€“a" OR TgtProcCmdLine containsCIS "â€”a" OR TgtProcCmdLine containsCIS "â€•a")))

```