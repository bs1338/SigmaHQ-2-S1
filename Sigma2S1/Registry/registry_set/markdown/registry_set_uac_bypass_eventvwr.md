# registry_set_uac_bypass_eventvwr

## Title
UAC Bypass via Event Viewer

## ID
7c81fec3-1c1d-43b0-996a-46753041b1b6

## Author
Florian Roth (Nextron Systems)

## Date
2017-03-19

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002, car.2019-04-001

## Description
Detects UAC bypass method using Windows event viewer

## References
https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "\mscfile\shell\open\command")

```