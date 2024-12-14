# registry_set_new_network_provider

## Title
Potential Credential Dumping Attempt Using New NetworkProvider - REG

## ID
0442defa-b4a2-41c9-ae2c-ea7042fc4701

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-23

## Tags
attack.credential-access, attack.t1003

## Description
Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it

## References
https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/network-provider-settings-removed-in-place-upgrade
https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy

## False Positives
Other legitimate network providers used and not filtred in this rule

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\System\CurrentControlSet\Services\" AND RegistryKeyPath containsCIS "\NetworkProvider") AND (NOT ((RegistryKeyPath containsCIS "\System\CurrentControlSet\Services\WebClient\NetworkProvider" OR RegistryKeyPath containsCIS "\System\CurrentControlSet\Services\LanmanWorkstation\NetworkProvider" OR RegistryKeyPath containsCIS "\System\CurrentControlSet\Services\RDPNP\NetworkProvider") OR SrcProcImagePath = "C:\Windows\System32\poqexec.exe"))))

```