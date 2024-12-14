# proc_creation_win_hktl_cobaltstrike_bloopers_cmd

## Title
Operator Bloopers Cobalt Strike Commands

## ID
647c7b9e-d784-4fda-b9a0-45c565a7b729

## Author
_pete_0, TheDFIRReport

## Date
2022-05-06

## Tags
attack.execution, attack.t1059.003, stp.1u

## Description
Detects use of Cobalt Strike commands accidentally entered in the CMD shell

## References
https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt-4-5-user-guide.pdf
https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/
https://thedfirreport.com/2022/06/16/sans-ransomware-summit-2022-can-you-detect-this/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "psinject" OR TgtProcCmdLine containsCIS "spawnas" OR TgtProcCmdLine containsCIS "make_token" OR TgtProcCmdLine containsCIS "remote-exec" OR TgtProcCmdLine containsCIS "rev2self" OR TgtProcCmdLine containsCIS "dcsync" OR TgtProcCmdLine containsCIS "logonpasswords" OR TgtProcCmdLine containsCIS "execute-assembly" OR TgtProcCmdLine containsCIS "getsystem") AND (TgtProcCmdLine startswithCIS "cmd " OR TgtProcCmdLine startswithCIS "cmd.exe" OR TgtProcCmdLine startswithCIS "c:\windows\system32\cmd.exe")) AND TgtProcImagePath endswithCIS "\cmd.exe"))

```