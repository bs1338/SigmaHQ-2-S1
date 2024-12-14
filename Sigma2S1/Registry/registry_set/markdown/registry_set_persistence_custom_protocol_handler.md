# registry_set_persistence_custom_protocol_handler

## Title
Potential Persistence Via Custom Protocol Handler

## ID
fdbf0b9d-0182-4c43-893b-a1eaab92d085

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-05-30

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects potential persistence activity via the registering of a new custom protocole handlers. While legitimate applications register protocole handlers often times during installation. And attacker can abuse this by setting a custom handler to be used as a persistence mechanism.

## References
https://ladydebug.com/blog/2019/06/21/custom-protocol-handler-cph/

## False Positives
Many legitimate applications can register a new custom protocol handler. Additional filters needs to applied according to your environment.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue startswithCIS "URL:" AND RegistryKeyPath startswithCIS "HKCR\") AND (NOT ((SrcProcImagePath startswithCIS "C:\Program Files (x86)" OR SrcProcImagePath startswithCIS "C:\Program Files\" OR SrcProcImagePath startswithCIS "C:\Windows\System32\" OR SrcProcImagePath startswithCIS "C:\Windows\SysWOW64\") OR RegistryValue startswithCIS "URL:ms-"))))

```