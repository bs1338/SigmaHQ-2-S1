# proc_creation_win_appvlp_uncommon_child_process

## Title
Uncommon Child Process Of Appvlp.EXE

## ID
9c7e131a-0f2c-4ae0-9d43-b04f4e266d43

## Author
Sreeman

## Date
2020-03-13

## Tags
attack.t1218, attack.defense-evasion, attack.execution

## Description
Detects uncommon child processes of Appvlp.EXE
Appvlp or the Application Virtualization Utility is included with Microsoft Office. Attackers are able to abuse "AppVLP" to execute shell commands.
Normally, this binary is used for Application Virtualization, but it can also be abused to circumvent the ASR file path rule folder
 or to mark a file as a system file.


## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Appvlp/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\appvlp.exe" AND (NOT (TgtProcImagePath endswithCIS ":\Windows\SysWOW64\rundll32.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\rundll32.exe")) AND (NOT ((TgtProcImagePath containsCIS ":\Program Files\Microsoft Office" AND TgtProcImagePath endswithCIS "\msoasb.exe") OR (TgtProcImagePath containsCIS ":\Program Files\Microsoft Office" AND TgtProcImagePath endswithCIS "\MSOUC.EXE") OR ((TgtProcImagePath containsCIS ":\Program Files\Microsoft Office" AND TgtProcImagePath containsCIS "\SkypeSrv\") AND TgtProcImagePath endswithCIS "\SKYPESERVER.EXE")))))

```