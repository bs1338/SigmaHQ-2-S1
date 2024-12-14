# registry_set_dhcp_calloutdll

## Title
DHCP Callout DLL Installation

## ID
9d3436ef-9476-4c43-acca-90ce06bdf33a

## Author
Dimitrios Slamaris

## Date
2017-05-15

## Tags
attack.defense-evasion, attack.t1574.002, attack.t1112

## Description
Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)

## References
https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\Services\DHCPServer\Parameters\CalloutDlls" OR RegistryKeyPath endswithCIS "\Services\DHCPServer\Parameters\CalloutEnabled"))

```