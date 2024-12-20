# proc_creation_win_registry_ie_security_zone_protocol_defaults_downgrade

## Title
IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI

## ID
10344bb3-7f65-46c2-b915-2d00d47be5b0

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-05

## Tags
attack.execution, attack.defense-evasion

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
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" AND TgtProcCmdLine containsCIS "http" AND TgtProcCmdLine containsCIS " 0"))

```