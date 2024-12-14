# registry_event_disable_wdigest_credential_guard

## Title
Wdigest CredGuard Registry Modification

## ID
1a2d6c47-75b0-45bd-b133-2c0be75349fd

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2019-08-25

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects potential malicious modification of the property value of IsCredGuardEnabled from
HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to disable Cred Guard on a system.
This is usually used with UseLogonCredential to manipulate the caching credentials.


## References
https://teamhydra.blog/2020/08/25/bypassing-credential-guard/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "\IsCredGuardEnabled")

```