# registry_set_optimize_file_sharing_network

## Title
MaxMpxCt Registry Value Changed

## ID
0e6a9e62-627e-496c-aef5-bfa39da29b5e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-03-19

## Tags
attack.defense-evasion, attack.t1070.005

## Description
Detects changes to the "MaxMpxCt" registry value.
MaxMpxCt specifies the maximum outstanding network requests for the server per client, which is used when negotiating a Server Message Block (SMB) connection with a client. Note if the value is set beyond 125 older Windows 9x clients will fail to negotiate.
Ransomware threat actors and operators (specifically BlackCat) were seen increasing this value in order to handle a higher volume of traffic.


## References
https://www.huntress.com/blog/blackcat-ransomware-affiliate-ttps
https://securityscorecard.com/research/deep-dive-into-alphv-blackcat-ransomware
https://www.intrinsec.com/alphv-ransomware-gang-analysis/?cn-reloaded=1
https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "\Services\LanmanServer\Parameters\MaxMpxCt")

```