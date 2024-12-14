# registry_set_custom_file_open_handler_powershell_execution

## Title
Custom File Open Handler Executes PowerShell

## ID
7530b96f-ad8e-431d-a04d-ac85cc461fdc

## Author
CD_R0M_

## Date
2022-06-11

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects the abuse of custom file open handler, executing powershell

## References
https://news.sophos.com/en-us/2022/02/01/solarmarker-campaign-used-novel-registry-changes-to-establish-persistence/?cmp=30728

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS "powershell" AND RegistryValue containsCIS "-command") AND RegistryKeyPath containsCIS "shell\open\command\"))

```