# registry_set_dns_server_level_plugin_dll

## Title
New DNS ServerLevelPluginDll Installed

## ID
e61e8a88-59a9-451c-874e-70fcc9740d67

## Author
Florian Roth (Nextron Systems)

## Date
2017-05-08

## Tags
attack.defense-evasion, attack.t1574.002, attack.t1112

## Description
Detects the installation of a DNS plugin DLL via ServerLevelPluginDll parameter in registry, which can be used to execute code in context of the DNS server (restart required)

## References
https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "\services\DNS\Parameters\ServerLevelPluginDll")

```