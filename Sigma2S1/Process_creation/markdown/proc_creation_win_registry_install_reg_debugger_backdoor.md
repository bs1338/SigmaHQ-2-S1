# proc_creation_win_registry_install_reg_debugger_backdoor

## Title
Suspicious Debugger Registration Cmdline

## ID
ae215552-081e-44c7-805f-be16f975c8a2

## Author
Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro

## Date
2019-09-06

## Tags
attack.persistence, attack.privilege-escalation, attack.t1546.008

## Description
Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).

## References
https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\CurrentVersion\Image File Execution Options\" AND (TgtProcCmdLine containsCIS "sethc.exe" OR TgtProcCmdLine containsCIS "utilman.exe" OR TgtProcCmdLine containsCIS "osk.exe" OR TgtProcCmdLine containsCIS "magnify.exe" OR TgtProcCmdLine containsCIS "narrator.exe" OR TgtProcCmdLine containsCIS "displayswitch.exe" OR TgtProcCmdLine containsCIS "atbroker.exe" OR TgtProcCmdLine containsCIS "HelpPane.exe")))

```