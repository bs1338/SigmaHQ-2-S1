# registry_event_add_local_hidden_user

## Title
Creation of a Local Hidden User Account by Registry

## ID
460479f3-80b7-42da-9c43-2cc1d54dbccd

## Author
Christian Burkard (Nextron Systems)

## Date
2021-05-03

## Tags
attack.persistence, attack.t1136.001

## Description
Sysmon registry detection of a local hidden user account.

## References
https://twitter.com/SBousseaden/status/1387530414185664538

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\lsass.exe" AND RegistryKeyPath containsCIS "\SAM\SAM\Domains\Account\Users\Names\" AND RegistryKeyPath endswithCIS "$"))

```