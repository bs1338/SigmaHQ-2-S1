# registry_set_persistence_scrobj_dll

## Title
Potential Persistence Via Scrobj.dll COM Hijacking

## ID
fe20dda1-6f37-4379-bbe0-a98d400cae90

## Author
frack113

## Date
2022-08-20

## Tags
attack.persistence, attack.t1546.015

## Description
Detect use of scrobj.dll as this DLL looks for the ScriptletURL key to get the location of the script to execute

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1546.015/T1546.015.md

## False Positives
Legitimate use of the dll.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "C:\WINDOWS\system32\scrobj.dll" AND RegistryKeyPath endswithCIS "InprocServer32\(Default)"))

```