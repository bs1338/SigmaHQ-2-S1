# registry_event_portproxy_registry_key

## Title
New PortProxy Registry Entry Added

## ID
a54f842a-3713-4b45-8c84-5f136fdebd3c

## Author
Andreas Hunkeler (@Karneades)

## Date
2021-06-22

## Tags
attack.lateral-movement, attack.defense-evasion, attack.command-and-control, attack.t1090

## Description
Detects the modification of the PortProxy registry key which is used for port forwarding.

## References
https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
https://adepts.of0x.cc/netsh-portproxy-code/
https://www.dfirnotes.net/portproxy_detection/

## False Positives
WSL2 network bridge PowerShell script used for WSL/Kubernetes/Docker (e.g. https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723)
Synergy Software KVM (https://symless.com/synergy)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\Services\PortProxy\v4tov4\tcp\")

```