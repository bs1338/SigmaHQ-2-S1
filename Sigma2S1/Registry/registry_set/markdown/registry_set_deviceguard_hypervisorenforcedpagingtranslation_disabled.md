# registry_set_deviceguard_hypervisorenforcedpagingtranslation_disabled

## Title
Hypervisor Enforced Paging Translation Disabled

## ID
7f2954d2-99c2-4d42-a065-ca36740f187b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-07-05

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects changes to the "DisableHypervisorEnforcedPagingTranslation" registry value. Where the it is set to "1" in order to disable the Hypervisor Enforced Paging Translation feature.


## References
https://twitter.com/standa_t/status/1808868985678803222
https://github.com/AaLl86/WindowsInternals/blob/070dc4f317726dfb6ffd2b7a7c121a33a8659b5e/Slides/Hypervisor-enforced%20Paging%20Translation%20-%20The%20end%20of%20non%20data-driven%20Kernel%20Exploits%20(Recon2024).pdf

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\DisableHypervisorEnforcedPagingTranslation"))

```