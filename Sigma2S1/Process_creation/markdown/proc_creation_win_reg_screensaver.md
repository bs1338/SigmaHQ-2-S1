# proc_creation_win_reg_screensaver

## Title
Suspicious ScreenSave Change by Reg.exe

## ID
0fc35fc3-efe6-4898-8a37-0b233339524f

## Author
frack113

## Date
2021-08-19

## Tags
attack.privilege-escalation, attack.t1546.002

## Description
Adversaries may establish persistence by executing malicious content triggered by user inactivity.
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md
https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf

## False Positives
GPO

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "HKEY_CURRENT_USER\Control Panel\Desktop" OR TgtProcCmdLine containsCIS "HKCU\Control Panel\Desktop") AND TgtProcImagePath endswithCIS "\reg.exe") AND ((TgtProcCmdLine containsCIS "/v ScreenSaveActive" AND TgtProcCmdLine containsCIS "/t REG_SZ" AND TgtProcCmdLine containsCIS "/d 1" AND TgtProcCmdLine containsCIS "/f") OR (TgtProcCmdLine containsCIS "/v ScreenSaveTimeout" AND TgtProcCmdLine containsCIS "/t REG_SZ" AND TgtProcCmdLine containsCIS "/d " AND TgtProcCmdLine containsCIS "/f") OR (TgtProcCmdLine containsCIS "/v ScreenSaverIsSecure" AND TgtProcCmdLine containsCIS "/t REG_SZ" AND TgtProcCmdLine containsCIS "/d 0" AND TgtProcCmdLine containsCIS "/f") OR (TgtProcCmdLine containsCIS "/v SCRNSAVE.EXE" AND TgtProcCmdLine containsCIS "/t REG_SZ" AND TgtProcCmdLine containsCIS "/d " AND TgtProcCmdLine containsCIS ".scr" AND TgtProcCmdLine containsCIS "/f"))))

```