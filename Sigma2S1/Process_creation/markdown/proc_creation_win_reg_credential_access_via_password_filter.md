# proc_creation_win_reg_credential_access_via_password_filter

## Title
Dropping Of Password Filter DLL

## ID
b7966f4a-b333-455b-8370-8ca53c229762

## Author
Sreeman

## Date
2020-10-29

## Tags
attack.credential-access, attack.t1556.002

## Description
Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS

## References
https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/
https://github.com/3gstudent/PasswordFilter/tree/master/PasswordFilter

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" AND TgtProcCmdLine containsCIS "scecli\0" AND TgtProcCmdLine containsCIS "reg add"))

```