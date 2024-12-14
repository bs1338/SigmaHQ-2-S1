# proc_creation_win_registry_new_network_provider

## Title
Potential Credential Dumping Attempt Using New NetworkProvider - CLI

## ID
baef1ec6-2ca9-47a3-97cc-4cf2bda10b77

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
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\System\CurrentControlSet\Services\" AND TgtProcCmdLine containsCIS "\NetworkProvider"))

```