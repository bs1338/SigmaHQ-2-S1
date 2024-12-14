# proc_creation_win_reg_lsa_disable_restricted_admin

## Title
RestrictedAdminMode Registry Value Tampering - ProcCreation

## ID
28ac00d6-22d9-4a3c-927f-bbd770104573

## Author
frack113

## Date
2023-01-13

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects changes to the "DisableRestrictedAdmin" registry value in order to disable or enable RestrictedAdmin mode.
RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system to which you connect using Remote Desktop.
This prevents your credentials from being harvested during the initial connection process if the remote server has been compromise


## References
https://github.com/redcanaryco/atomic-red-team/blob/a8e3cf63e97b973a25903d3df9fd55da6252e564/atomics/T1112/T1112.md
https://social.technet.microsoft.com/wiki/contents/articles/32905.remote-desktop-services-enable-restricted-admin-mode.aspx
https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\System\CurrentControlSet\Control\Lsa\" AND TgtProcCmdLine containsCIS "DisableRestrictedAdmin"))

```