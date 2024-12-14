# registry_delete_mstsc_history_cleared

## Title
Terminal Server Client Connection History Cleared - Registry

## ID
07bdd2f5-9c58-4f38-aec8-e101bb79ef8d

## Author
Christian Burkard (Nextron Systems)

## Date
2021-10-19

## Tags
attack.defense-evasion, attack.t1070, attack.t1112

## Description
Detects the deletion of registry keys containing the MSTSC connection history

## References
https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remove-entries-from-remote-desktop-connection-computer
http://woshub.com/how-to-clear-rdp-connections-history/
https://www.trendmicro.com/en_us/research/23/a/vice-society-ransomware-group-targets-manufacturing-companies.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "DeleteValue" AND RegistryKeyPath containsCIS "\Microsoft\Terminal Server Client\Default\MRU") OR (EventType = "DeleteKey" AND RegistryKeyPath containsCIS "\Microsoft\Terminal Server Client\Servers\")))

```