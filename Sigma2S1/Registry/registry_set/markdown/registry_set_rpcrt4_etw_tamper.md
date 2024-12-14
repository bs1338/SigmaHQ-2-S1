# registry_set_rpcrt4_etw_tamper

## Title
ETW Logging Disabled For rpcrt4.dll

## ID
90f342e1-1aaa-4e43-b092-39fda57ed11e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-09

## Tags
attack.defense-evasion, attack.t1112, attack.t1562

## Description
Detects changes to the "ExtErrorInformation" key in order to disable ETW logging for rpcrt4.dll

## References
http://redplait.blogspot.com/2020/07/whats-wrong-with-etw.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue In Contains AnyCase ("DWORD (0x00000000)","DWORD (0x00000002)")) AND RegistryKeyPath endswithCIS "\Microsoft\Windows NT\Rpc\ExtErrorInformation"))

```