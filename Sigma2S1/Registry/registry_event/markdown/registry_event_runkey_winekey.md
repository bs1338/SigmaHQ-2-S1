# registry_event_runkey_winekey

## Title
WINEKEY Registry Modification

## ID
b98968aa-dbc0-4a9c-ac35-108363cbf8d5

## Author
omkar72

## Date
2020-10-30

## Tags
attack.persistence, attack.t1547

## Description
Detects potential malicious modification of run keys by winekey or team9 backdoor

## References
https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "Software\Microsoft\Windows\CurrentVersion\Run\Backup Mgr")

```