# registry_set_legalnotice_susp_message

## Title
Potential Ransomware Activity Using LegalNotice Message

## ID
8b9606c9-28be-4a38-b146-0e313cc232c1

## Author
frack113

## Date
2022-12-11

## Tags
attack.impact, attack.t1491.001

## Description
Detect changes to the "LegalNoticeCaption" or "LegalNoticeText" registry values where the message set contains keywords often used in ransomware ransom messages

## References
https://github.com/redcanaryco/atomic-red-team/blob/5c1e6f1b4fafd01c8d1ece85f510160fc1275fbf/atomics/T1491.001/T1491.001.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS "encrypted" OR RegistryValue containsCIS "Unlock-Password" OR RegistryValue containsCIS "paying") AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText")))

```