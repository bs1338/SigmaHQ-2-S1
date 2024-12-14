# registry_event_net_ntlm_downgrade

## Title
NetNTLM Downgrade Attack - Registry

## ID
d67572a0-e2ec-45d6-b8db-c100d14b8ef2

## Author
Florian Roth (Nextron Systems), wagga, Nasreddine Bencherchali (Splunk STRT)

## Date
2018-03-20

## Tags
attack.defense-evasion, attack.t1562.001, attack.t1112

## Description
Detects NetNTLM downgrade attack

## References
https://web.archive.org/web/20171113231705/https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=NSrpcservers

## False Positives
Services or tools that set the values to more restrictive values

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "SYSTEM\" AND RegistryKeyPath containsCIS "ControlSet" AND RegistryKeyPath containsCIS "\Control\Lsa") AND (((RegistryValue In Contains AnyCase ("DWORD (0x00000000)","DWORD (0x00000001)","DWORD (0x00000002)")) AND RegistryKeyPath endswithCIS "\lmcompatibilitylevel") OR ((RegistryValue In Contains AnyCase ("DWORD (0x00000000)","DWORD (0x00000010)","DWORD (0x00000020)","DWORD (0x00000030)")) AND RegistryKeyPath endswithCIS "\NtlmMinClientSec") OR RegistryKeyPath endswithCIS "\RestrictSendingNTLMTraffic")))

```