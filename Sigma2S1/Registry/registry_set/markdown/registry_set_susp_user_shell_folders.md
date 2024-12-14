# registry_set_susp_user_shell_folders

## Title
Modify User Shell Folders Startup Value

## ID
9c226817-8dc9-46c2-a58d-66655aafd7dc

## Author
frack113

## Date
2022-10-01

## Tags
attack.persistence, attack.privilege-escalation, attack.t1547.001

## Description
Detect modification of the startup key to a path where a payload could be stored to be launched during startup

## References
https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1547.001/T1547.001.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" AND RegistryKeyPath endswithCIS "Startup"))

```