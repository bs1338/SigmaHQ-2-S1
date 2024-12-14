# registry_event_runonce_persistence

## Title
Run Once Task Configuration in Registry

## ID
c74d7efc-8826-45d9-b8bb-f04fac9e4eff

## Author
Avneet Singh @v3t0_, oscd.community

## Date
2020-11-15

## Tags
attack.defense-evasion, attack.t1112

## Description
Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup

## References
https://twitter.com/pabraeken/status/990717080805789697
https://lolbas-project.github.io/lolbas/Binaries/Runonce/

## False Positives
Legitimate modification of the registry key by legitimate program

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Microsoft\Active Setup\Installed Components" AND RegistryKeyPath endswithCIS "\StubPath") AND (NOT ((RegistryValue containsCIS "C:\Program Files\Google\Chrome\Application\" AND RegistryValue containsCIS "\Installer\chrmstp.exe\" --configure-user-settings --verbose-logging --system-level") OR ((RegistryValue containsCIS "C:\Program Files (x86)\Microsoft\Edge\Application\" OR RegistryValue containsCIS "C:\Program Files\Microsoft\Edge\Application\") AND RegistryValue endswithCIS "\Installer\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable")))))

```