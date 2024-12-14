# registry_set_hvci_disallowed_images

## Title
Driver Added To Disallowed Images In HVCI - Registry

## ID
555155a2-03bf-4fe7-af74-d176b3fdbe16

## Author
Nasreddine Bencherchali (Nextron Systems), Omar Khaled (@beacon_exe)

## Date
2023-12-05

## Tags
attack.defense-evasion

## Description
Detects changes to the "HVCIDisallowedImages" registry value to potentially add a driver to the list, in order to prevent it from loading.


## References
https://github.com/yardenshafir/conference_talks/blob/3de1f5d7c02656c35117f067fbff0a219c304b09/OffensiveCon_2023_Your_Mitigations_are_My_Opportunities.pdf
https://x.com/yarden_shafir/status/1822667605175324787

## False Positives
Legitimate usage of this key would also trigger this. Investigate the driver being added and make sure its intended

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Control\CI\" AND RegistryKeyPath containsCIS "\HVCIDisallowedImages"))

```