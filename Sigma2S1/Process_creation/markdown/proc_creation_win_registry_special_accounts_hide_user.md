# proc_creation_win_registry_special_accounts_hide_user

## Title
Hiding User Account Via SpecialAccounts Registry Key - CommandLine

## ID
9ec9fb1b-e059-4489-9642-f270c207923d

## Author
@Kostastsale, @TheDFIRReport

## Date
2022-05-14

## Tags
attack.t1564.002

## Description
Detects changes to the registry key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" where the value is set to "0" in order to hide user account from being listed on the logon screen.


## References
https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/
https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion/
https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/
https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/

## False Positives
System administrator activities

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "/v" AND TgtProcCmdLine containsCIS "/d 0") AND TgtProcImagePath endswithCIS "\reg.exe"))

```