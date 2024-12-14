# proc_creation_win_sc_sdset_allow_service_changes

## Title
Allow Service Access Using Security Descriptor Tampering Via Sc.EXE

## ID
6c8fbee5-dee8-49bc-851d-c3142d02aa47

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-28

## Tags
attack.persistence, attack.t1543.003

## Description
Detects suspicious DACL modifications to allow access to a service from a suspicious trustee. This can be used to override access restrictions set by previous ACLs.

## References
https://twitter.com/0gtweet/status/1628720819537936386
https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/
https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\sc.exe" AND (TgtProcCmdLine containsCIS "sdset" AND TgtProcCmdLine containsCIS "A;") AND (TgtProcCmdLine containsCIS ";IU" OR TgtProcCmdLine containsCIS ";SU" OR TgtProcCmdLine containsCIS ";BA" OR TgtProcCmdLine containsCIS ";SY" OR TgtProcCmdLine containsCIS ";WD")))

```