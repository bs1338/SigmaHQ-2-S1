# proc_creation_win_lolbin_ie4uinit

## Title
Ie4uinit Lolbin Use From Invalid Path

## ID
d3bf399f-b0cf-4250-8bb4-dfc192ab81dc

## Author
frack113

## Date
2022-05-07

## Tags
attack.defense-evasion, attack.t1218

## Description
Detect use of ie4uinit.exe to execute commands from a specially prepared ie4uinit.inf file from a directory other than the usual directories

## References
https://lolbas-project.github.io/lolbas/Binaries/Ie4uinit/
https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/

## False Positives
ViberPC updater calls this binary with the following commandline "ie4uinit.exe -ClearIconCache"

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\ie4uinit.exe" AND (NOT ((TgtProcImagePath In Contains AnyCase ("c:\windows\system32\","c:\windows\sysWOW64\")) OR TgtProcImagePath IS NOT EMPTY))))

```