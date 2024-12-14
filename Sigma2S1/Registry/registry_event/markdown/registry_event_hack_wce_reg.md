# registry_event_hack_wce_reg

## Title
Windows Credential Editor Registry

## ID
a6b33c02-8305-488f-8585-03cb2a7763f2

## Author
Florian Roth (Nextron Systems)

## Date
2019-12-31

## Tags
attack.credential-access, attack.t1003.001, attack.s0005

## Description
Detects the use of Windows Credential Editor (WCE)

## References
https://www.ampliasecurity.com/research/windows-credentials-editor/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "Services\WCESERVICE\Start")

```