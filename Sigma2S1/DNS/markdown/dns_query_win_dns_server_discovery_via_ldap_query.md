# dns_query_win_dns_server_discovery_via_ldap_query

## Title
DNS Server Discovery Via LDAP Query

## ID
a21bcd7e-38ec-49ad-b69a-9ea17e69509e

## Author
frack113

## Date
2022-08-20

## Tags
attack.discovery, attack.t1482

## Description
Detects DNS server discovery via LDAP query requests from uncommon applications

## References
https://github.com/redcanaryco/atomic-red-team/blob/980f3f83fd81f37c1ca9c02dccfd1c3d9f9d0841/atomics/T1016/T1016.md#atomic-test-9---dns-server-discovery-using-nslookup
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04

## False Positives
Likely

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (DnsRequest startswithCIS "_ldap." AND (NOT ((SrcProcImagePath containsCIS ":\ProgramData\Microsoft\Windows Defender\Platform\" AND SrcProcImagePath endswithCIS "\MsMpEng.exe") OR (SrcProcImagePath containsCIS ":\Program Files\" OR SrcProcImagePath containsCIS ":\Program Files (x86)\" OR SrcProcImagePath containsCIS ":\Windows\") OR SrcProcImagePath IS NOT EMPTY OR SrcProcImagePath = "<unknown process>")) AND (NOT (SrcProcImagePath startswithCIS "C:\WindowsAzure\GuestAgent" OR (SrcProcImagePath endswithCIS "\chrome.exe" OR SrcProcImagePath endswithCIS "\firefox.exe" OR SrcProcImagePath endswithCIS "\opera.exe")))))

```