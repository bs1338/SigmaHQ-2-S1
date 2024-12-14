# registry_set_fax_change_service_user

## Title
Change User Account Associated with the FAX Service

## ID
e3fdf743-f05b-4051-990a-b66919be1743

## Author
frack113

## Date
2022-07-17

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect change of the user account associated with the FAX service to avoid the escalation problem.

## References
https://twitter.com/dottor_morte/status/1544652325570191361
https://raw.githubusercontent.com/RiccardoAncarani/talks/master/F-Secure/unorthodox-lateral-movement.pdf

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath = "HKLM\System\CurrentControlSet\Services\Fax\ObjectName" AND (NOT RegistryValue containsCIS "NetworkService")))

```