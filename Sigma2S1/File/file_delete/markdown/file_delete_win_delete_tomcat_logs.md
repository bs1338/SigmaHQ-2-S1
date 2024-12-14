# file_delete_win_delete_tomcat_logs

## Title
Tomcat WebServer Logs Deleted

## ID
270185ff-5f50-4d6d-a27f-24c3b8c9fef8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-16

## Tags
attack.defense-evasion, attack.t1070

## Description
Detects the deletion of tomcat WebServer logs which may indicate an attempt to destroy forensic evidence

## References
Internal Research
https://linuxhint.com/view-tomcat-logs-windows/

## False Positives
During uninstallation of the tomcat server
During log rotation

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "catalina." OR TgtFilePath containsCIS "_access_log." OR TgtFilePath containsCIS "localhost.") AND (TgtFilePath containsCIS "\Tomcat" AND TgtFilePath containsCIS "\logs\")))

```