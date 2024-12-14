# registry_set_change_winevt_channelaccess

## Title
Change Winevt Channel Access Permission Via Registry

## ID
7d9263bd-dc47-4a58-bc92-5474abab390c

## Author
frack113

## Date
2022-09-17

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Detects tampering with the "ChannelAccess" registry key in order to change access to Windows event channel.

## References
https://app.any.run/tasks/77b2e328-8f36-46b2-b2e2-8a80398217ab/
https://learn.microsoft.com/en-us/windows/win32/api/winevt/
https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue containsCIS "(A;;0x1;;;LA)" OR RegistryValue containsCIS "(A;;0x1;;;SY)" OR RegistryValue containsCIS "(A;;0x5;;;BA)") AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\" AND RegistryKeyPath endswithCIS "\ChannelAccess") AND (NOT ((SrcProcImagePath endswithCIS "\TiWorker.exe" AND SrcProcImagePath startswithCIS "C:\Windows\WinSxS\") OR SrcProcImagePath = "C:\Windows\servicing\TrustedInstaller.exe"))))

```