# registry_set_sophos_av_tamper

## Title
Tamper With Sophos AV Registry Keys

## ID
9f4662ac-17ca-43aa-8f12-5d7b989d0101

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-02

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects tamper attempts to sophos av functionality via registry key modification

## References
https://redacted.com/blog/bianlian-ransomware-gang-gives-it-a-go/

## False Positives
Some FP may occur when the feature is disabled by the AV itself, you should always investigate if the action was legitimate

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath containsCIS "\Sophos Endpoint Defense\TamperProtection\Config\SAVEnabled" OR RegistryKeyPath containsCIS "\Sophos Endpoint Defense\TamperProtection\Config\SEDEnabled" OR RegistryKeyPath containsCIS "\Sophos\SAVService\TamperProtection\Enabled")))

```