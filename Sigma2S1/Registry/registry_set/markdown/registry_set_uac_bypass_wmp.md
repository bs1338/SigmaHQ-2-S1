# registry_set_uac_bypass_wmp

## Title
UAC Bypass Using Windows Media Player - Registry

## ID
5f9db380-ea57-4d1e-beab-8a2d33397e93

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-23

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "Binary Data" AND RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Program Files\Windows Media Player\osk.exe"))

```