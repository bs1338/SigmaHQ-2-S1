# proc_creation_win_reg_open_command

## Title
Suspicious Reg Add Open Command

## ID
dd3ee8cc-f751-41c9-ba53-5a32ed47e563

## Author
frack113

## Date
2021-12-20

## Tags
attack.credential-access, attack.t1003

## Description
Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using DelegateExecute key

## References
https://thedfirreport.com/2021/12/13/diavol-ransomware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "reg" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "hkcu\software\classes\ms-settings\shell\open\command" AND TgtProcCmdLine containsCIS "/ve " AND TgtProcCmdLine containsCIS "/d") OR (TgtProcCmdLine containsCIS "reg" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "hkcu\software\classes\ms-settings\shell\open\command" AND TgtProcCmdLine containsCIS "/v" AND TgtProcCmdLine containsCIS "DelegateExecute") OR (TgtProcCmdLine containsCIS "reg" AND TgtProcCmdLine containsCIS "delete" AND TgtProcCmdLine containsCIS "hkcu\software\classes\ms-settings")))

```