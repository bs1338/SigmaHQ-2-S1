# registry_set_disable_autologger_sessions

## Title
Potential AutoLogger Sessions Tampering

## ID
f37b4bce-49d0-4087-9f5b-58bffda77316

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-01

## Tags
attack.defense-evasion

## Description
Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging

## References
https://twitter.com/MichalKoczwara/status/1553634816016498688
https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\System\CurrentControlSet\Control\WMI\Autologger\" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath containsCIS "\EventLog-" OR RegistryKeyPath containsCIS "\Defender") AND (RegistryKeyPath endswithCIS "\Enable" OR RegistryKeyPath endswithCIS "\Start"))) AND (NOT SrcProcImagePath = "C:\Windows\system32\wevtutil.exe")))

```