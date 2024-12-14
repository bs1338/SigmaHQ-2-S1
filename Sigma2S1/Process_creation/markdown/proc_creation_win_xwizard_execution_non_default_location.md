# proc_creation_win_xwizard_execution_non_default_location

## Title
Xwizard.EXE Execution From Non-Default Location

## ID
193d5ccd-6f59-40c6-b5b0-8e32d5ddd3d1

## Author
Christian Burkard (Nextron Systems)

## Date
2021-09-20

## Tags
attack.defense-evasion, attack.t1574.002

## Description
Detects the execution of Xwizard tool from a non-default directory.
 When executed from a non-default directory, this utility can be abused in order to side load a custom version of "xwizards.dll".


## References
https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/

## False Positives
Windows installed on non-C drive

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\xwizard.exe" AND (NOT (TgtProcImagePath startswithCIS "C:\Windows\System32\" OR TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\" OR TgtProcImagePath startswithCIS "C:\Windows\WinSxS\"))))

```