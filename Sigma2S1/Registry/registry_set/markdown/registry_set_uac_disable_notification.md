# registry_set_uac_disable_notification

## Title
UAC Notification Disabled

## ID
c5f6a85d-b647-40f7-bbad-c10b66bab038

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2024-05-10

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1548.002

## Description
Detects when an attacker tries to disable User Account Control (UAC) notification by tampering with the "UACDisableNotify" value.
UAC is a critical security feature in Windows that prevents unauthorized changes to the operating system. It prompts the user for permission or an administrator password before allowing actions that could affect the system's operation or change settings that affect other users.
When "UACDisableNotify" is set to 1, UAC prompts are suppressed.


## References
https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md
https://securityintelligence.com/x-force/x-force-hive0129-targeting-financial-institutions-latam-banking-trojan/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath containsCIS "\Microsoft\Security Center\UACDisableNotify"))

```