# registry_set_susp_reg_persist_explorer_run

## Title
Registry Persistence via Explorer Run Key

## ID
b7916c2a-fa2f-4795-9477-32b731f70f11

## Author
Florian Roth (Nextron Systems), oscd.community

## Date
2018-07-18

## Tags
attack.persistence, attack.t1547.001

## Description
Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder

## References
https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS ":\$Recycle.bin\" OR RegistryValue containsCIS ":\ProgramData\" OR RegistryValue containsCIS ":\Temp\" OR RegistryValue containsCIS ":\Users\Default\" OR RegistryValue containsCIS ":\Users\Public\" OR RegistryValue containsCIS ":\Windows\Temp\" OR RegistryValue containsCIS "\AppData\Local\Temp\") AND RegistryKeyPath endswithCIS "\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"))

```