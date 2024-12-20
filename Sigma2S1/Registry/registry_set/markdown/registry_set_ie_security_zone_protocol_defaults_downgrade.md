# registry_set_ie_security_zone_protocol_defaults_downgrade

## Title
IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols

## ID
3fd4c8d7-8362-4557-a8e6-83b29cc0d724

## Author
Nasreddine Bencherchali (Nextron Systems), Michael Haag (idea)

## Date
2023-09-05

## Tags
attack.defense-evasion

## Description
Detects changes to Internet Explorer's (IE / Windows Internet properties) ZoneMap configuration of the "HTTP" and "HTTPS" protocols to point to the "My Computer" zone. This allows downloaded files from the Internet to be granted the same level of trust as files stored locally.


## References
https://twitter.com/M_haggis/status/1699056847154725107
https://twitter.com/JAMESWT_MHT/status/1699042827261391247
https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries
https://www.virustotal.com/gui/file/339ff720c74dc44265b917b6d3e3ba0411d61f3cd3c328e9a2bae81592c8a6e5/content

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue containsCIS "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" AND (RegistryKeyPath endswithCIS "\http" OR RegistryKeyPath endswithCIS "\https")))

```