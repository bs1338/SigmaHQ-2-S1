# registry_event_bypass_via_wsreset

## Title
UAC Bypass Via Wsreset

## ID
6ea3bf32-9680-422d-9f50-e90716b12a66

## Author
oscd.community, Dmitry Uchakin

## Date
2020-10-07

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Unfixed method for UAC bypass from Windows 10. WSReset.exe file associated with the Windows Store. It will run a binary file contained in a low-privilege registry.

## References
https://www.bleepingcomputer.com/news/security/trickbot-uses-a-new-windows-10-uac-bypass-to-launch-quietly
https://lolbas-project.github.io/lolbas/Binaries/Wsreset

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command")

```