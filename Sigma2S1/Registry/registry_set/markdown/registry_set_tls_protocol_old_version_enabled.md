# registry_set_tls_protocol_old_version_enabled

## Title
Old TLS1.0/TLS1.1 Protocol Version Enabled

## ID
439957a7-ad86-4a8f-9705-a28131c6821b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-05

## Tags
attack.defense-evasion

## Description
Detects applications or users re-enabling old TLS versions by setting the "Enabled" value to "1" for the "Protocols" registry key.

## References
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/tls-1-0-and-tls-1-1-soon-to-be-disabled-in-windows/ba-p/3887947

## False Positives
Legitimate enabling of the old tls versions due to incompatibility

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath containsCIS "\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\" OR RegistryKeyPath containsCIS "\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\") AND RegistryKeyPath endswithCIS "\Enabled"))

```