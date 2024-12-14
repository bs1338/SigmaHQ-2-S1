# registry_set_disable_winevt_logging

## Title
Disable Windows Event Logging Via Registry

## ID
2f78da12-f7c7-430b-8b19-a28f269b77a3

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-04

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Detects tampering with the "Enabled" registry key in order to disable Windows logging of a Windows event channel

## References
https://twitter.com/WhichbufferArda/status/1543900539280293889
https://github.com/DebugPrivilege/CPP/blob/c39d365617dbfbcb01fffad200d52b6239b2918c/Windows%20Defender/RestoreDefenderConfig.cpp

## False Positives
Rare falsepositives may occur from legitimate administrators disabling specific event log for troubleshooting

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\" AND RegistryKeyPath endswithCIS "\Enabled") AND (NOT ((SrcProcImagePath endswithCIS "\TiWorker.exe" AND SrcProcImagePath startswithCIS "C:\Windows\winsxs\") OR (SrcProcImagePath = "C:\Windows\System32\svchost.exe" AND (RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileInfoMinifilter" OR RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ASN1\" OR RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat\" OR RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime\Error\" OR RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational\")) OR (SrcProcImagePath = "C:\Windows\servicing\TrustedInstaller.exe" AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Compat-Appraiser") OR SrcProcImagePath = "C:\Windows\system32\wevtutil.exe")) AND (NOT (SrcProcImagePath = "" OR SrcProcImagePath IS NOT EMPTY))))

```