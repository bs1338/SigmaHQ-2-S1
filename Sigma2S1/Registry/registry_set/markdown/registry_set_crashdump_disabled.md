# registry_set_crashdump_disabled

## Title
CrashControl CrashDump Disabled

## ID
2ff692c2-4594-41ec-8fcb-46587de769e0

## Author
Tobias Michalski (Nextron Systems)

## Date
2022-02-24

## Tags
attack.t1564, attack.t1112

## Description
Detects disabling the CrashDump per registry (as used by HermeticWiper)

## References
https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/

## False Positives
Legitimate disabling of crashdumps

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "SYSTEM\CurrentControlSet\Control\CrashControl"))

```