# registry_set_uac_disable

## Title
UAC Disabled

## ID
48437c39-9e5f-47fb-af95-3d663c3f2919

## Author
frack113

## Date
2022-01-05

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1548.002

## Description
Detects when an attacker tries to disable User Account Control (UAC) by setting the registry value "EnableLUA" to 0.


## References
https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"))

```