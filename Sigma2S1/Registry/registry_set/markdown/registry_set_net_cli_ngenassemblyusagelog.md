# registry_set_net_cli_ngenassemblyusagelog

## Title
NET NGenAssemblyUsageLog Registry Key Tamper

## ID
28036918-04d3-423d-91c0-55ecf99fb892

## Author
frack113

## Date
2022-11-18

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects changes to the NGenAssemblyUsageLog registry key.
.NET Usage Log output location can be controlled by setting the NGenAssemblyUsageLog CLR configuration knob in the Registry or by configuring an environment variable (as described in the next section).
By simplify specifying an arbitrary value (e.g. fake output location or junk data) for the expected value, a Usage Log file for the .NET execution context will not be created.


## References
https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\.NETFramework\NGenAssemblyUsageLog")

```