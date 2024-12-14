# proc_creation_win_cmd_mklink_osk_cmd

## Title
Potential Privilege Escalation Using Symlink Between Osk and Cmd

## ID
e9b61244-893f-427c-b287-3e708f321c6b

## Author
frack113

## Date
2022-12-11

## Tags
attack.privilege-escalation, attack.persistence, attack.t1546.008

## Description
Detects the creation of a symbolic link between "cmd.exe" and the accessibility on-screen keyboard binary (osk.exe) using "mklink". This technique provides an elevated command prompt to the user from the login screen without the need to log in.

## References
https://github.com/redcanaryco/atomic-red-team/blob/5c1e6f1b4fafd01c8d1ece85f510160fc1275fbf/atomics/T1546.008/T1546.008.md
https://ss64.com/nt/mklink.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "mklink" AND TgtProcCmdLine containsCIS "\osk.exe" AND TgtProcCmdLine containsCIS "\cmd.exe") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```