# registry_set_disabled_microsoft_defender_eventlog

## Title
Disabled Windows Defender Eventlog

## ID
fcddca7c-b9c0-4ddf-98da-e1e2d18b0157

## Author
Florian Roth (Nextron Systems)

## Date
2022-07-04

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the disabling of the Windows Defender eventlog as seen in relation to Lockbit 3.0 infections

## References
https://twitter.com/WhichbufferArda/status/1543900539280293889/photo/2

## False Positives
Other Antivirus software installations could cause Windows to disable that eventlog (unknown)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational\Enabled"))

```