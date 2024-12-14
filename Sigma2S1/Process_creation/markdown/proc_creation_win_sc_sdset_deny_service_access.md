# proc_creation_win_sc_sdset_deny_service_access

## Title
Deny Service Access Using Security Descriptor Tampering Via Sc.EXE

## ID
99cf1e02-00fb-4c0d-8375-563f978dfd37

## Author
Jonhnathan Ribeiro, oscd.community

## Date
2020-10-16

## Tags
attack.persistence, attack.t1543.003

## Description
Detects suspicious DACL modifications to deny access to a service that affects critical trustees. This can be used to hide services or make them unstoppable.

## References
https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/
https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\sc.exe" AND (TgtProcCmdLine containsCIS "sdset" AND TgtProcCmdLine containsCIS "D;") AND (TgtProcCmdLine containsCIS ";IU" OR TgtProcCmdLine containsCIS ";SU" OR TgtProcCmdLine containsCIS ";BA" OR TgtProcCmdLine containsCIS ";SY" OR TgtProcCmdLine containsCIS ";WD")))

```