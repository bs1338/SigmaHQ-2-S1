# registry_set_deviceguard_hypervisorenforcedcodeintegrity_disabled

## Title
Hypervisor Enforced Code Integrity Disabled

## ID
8b7273a4-ba5d-4d8a-b04f-11f2900d043a

## Author
Nasreddine Bencherchali (Nextron Systems), Anish Bogati

## Date
2023-03-14

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects changes to the HypervisorEnforcedCodeIntegrity registry key and the "Enabled" value being set to 0 in order to disable the Hypervisor Enforced Code Integrity feature. This allows an attacker to load unsigned and untrusted code to be run in the kernel


## References
https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/
https://github.com/redcanaryco/atomic-red-team/blob/04e487c1828d76df3e834621f4f893ea756d5232/atomics/T1562.001/T1562.001.md#atomic-test-43---disable-hypervisor-enforced-code-integrity-hvci

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity" OR RegistryKeyPath endswithCIS "\Control\DeviceGuard\HypervisorEnforcedCodeIntegrity" OR RegistryKeyPath endswithCIS "\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled")))

```