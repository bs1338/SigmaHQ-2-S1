# registry_set_lsa_disablerestrictedadmin

## Title
RestrictedAdminMode Registry Value Tampering

## ID
d6ce7ebd-260b-4323-9768-a9631c8d4db2

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

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin")

```