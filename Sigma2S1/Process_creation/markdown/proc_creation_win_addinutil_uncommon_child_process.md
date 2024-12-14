# proc_creation_win_addinutil_uncommon_child_process

## Title
Uncommon Child Process Of AddinUtil.EXE

## ID
b5746143-59d6-4603-8d06-acbd60e166ee

## Author
Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)

## Date
2023-09-18

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects uncommon child processes of the Add-In deployment cache updating utility (AddInutil.exe) which could be a sign of potential abuse of the binary to proxy execution via a custom Addins.Store payload.


## References
https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\addinutil.exe" AND (NOT (TgtProcImagePath endswithCIS ":\Windows\System32\conhost.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\werfault.exe" OR TgtProcImagePath endswithCIS ":\Windows\SysWOW64\werfault.exe"))))

```