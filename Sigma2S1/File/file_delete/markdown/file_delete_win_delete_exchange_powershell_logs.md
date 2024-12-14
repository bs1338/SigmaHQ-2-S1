# file_delete_win_delete_exchange_powershell_logs

## Title
Exchange PowerShell Cmdlet History Deleted

## ID
a55349d8-9588-4c5a-8e3b-1925fe2a4ffe

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-26

## Tags
attack.defense-evasion, attack.t1070

## Description
Detects the deletion of the Exchange PowerShell cmdlet History logs which may indicate an attempt to destroy forensic evidence

## References
https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/

## False Positives
Possible FP during log rotation

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "_Cmdlet_" AND TgtFilePath startswithCIS "\Logging\CmdletInfra\LocalPowerShell\Cmdlet\"))

```