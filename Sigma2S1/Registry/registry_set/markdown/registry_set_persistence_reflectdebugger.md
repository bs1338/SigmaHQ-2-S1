# registry_set_persistence_reflectdebugger

## Title
Potential WerFault ReflectDebugger Registry Value Abuse

## ID
0cf2e1c6-8d10-4273-8059-738778f981ad

## Author
X__Junior

## Date
2023-05-18

## Tags
attack.defense-evasion, attack.t1036.003

## Description
Detects potential WerFault "ReflectDebugger" registry value abuse for persistence.

## References
https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (EventType = "SetValue" AND RegistryKeyPath endswithCIS "\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger"))

```