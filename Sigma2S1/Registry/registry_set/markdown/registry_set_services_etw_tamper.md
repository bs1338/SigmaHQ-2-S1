# registry_set_services_etw_tamper

## Title
ETW Logging Disabled For SCM

## ID
4f281b83-0200-4b34-bf35-d24687ea57c2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-09

## Tags
attack.defense-evasion, attack.t1112, attack.t1562

## Description
Detects changes to the "TracingDisabled" key in order to disable ETW logging for services.exe (SCM)

## References
http://redplait.blogspot.com/2020/07/whats-wrong-with-etw.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular\TracingDisabled"))

```