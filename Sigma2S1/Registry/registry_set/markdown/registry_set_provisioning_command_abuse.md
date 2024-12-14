# registry_set_provisioning_command_abuse

## Title
Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG

## ID
7021255e-5db3-4946-a8b9-0ba7a4644a69

## Author
Swachchhanda Shrawan Poudel

## Date
2023-08-02

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects potential abuse of the provisioning registry key for indirect command execution through "Provlaunch.exe".

## References
https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
https://twitter.com/0gtweet/status/1674399582162153472

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Provisioning\Commands\")

```