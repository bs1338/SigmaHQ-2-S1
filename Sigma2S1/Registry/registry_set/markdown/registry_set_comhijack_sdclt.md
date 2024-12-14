# registry_set_comhijack_sdclt

## Title
COM Hijack via Sdclt

## ID
07743f65-7ec9-404a-a519-913db7118a8d

## Author
Omkar Gudhate

## Date
2020-09-27

## Tags
attack.privilege-escalation, attack.t1546, attack.t1548

## Description
Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'

## References
http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
https://www.exploit-db.com/exploits/47696

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\Software\Classes\Folder\shell\open\command\DelegateExecute")

```