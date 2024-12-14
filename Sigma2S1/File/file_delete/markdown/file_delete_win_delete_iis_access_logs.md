# file_delete_win_delete_iis_access_logs

## Title
IIS WebServer Access Logs Deleted

## ID
3eb8c339-a765-48cc-a150-4364c04652bf

## Author
Tim Rauch (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-16

## Tags
attack.defense-evasion, attack.t1070

## Description
Detects the deletion of IIS WebServer access logs which may indicate an attempt to destroy forensic evidence

## References
https://www.elastic.co/guide/en/security/current/webserver-access-logs-deleted.html

## False Positives
During uninstallation of the IIS service
During log rotation

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "\inetpub\logs\LogFiles\" AND TgtFilePath endswithCIS ".log"))

```