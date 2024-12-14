# registry_set_special_accounts

## Title
Hiding User Account Via SpecialAccounts Registry Key

## ID
f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2022-07-12

## Tags
attack.defense-evasion, attack.t1564.002

## Description
Detects modifications to the registry key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" where the value is set to "0" in order to hide user account from being listed on the logon screen.

## References
https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1564.002/T1564.002.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND EventType = "SetValue" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"))

```