# registry_set_disallowrun_execution

## Title
Add DisallowRun Execution to Registry

## ID
275641a5-a492-45e2-a817-7c81e9d9d3e9

## Author
frack113

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect set DisallowRun to 1 to prevent user running specific computer program

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"))

```