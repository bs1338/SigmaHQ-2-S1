# proc_creation_win_iis_connection_strings_decryption

## Title
Microsoft IIS Connection Strings Decryption

## ID
97dbf6e2-e436-44d8-abee-4261b24d3e41

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-28

## Tags
attack.credential-access, attack.t1003

## Description
Detects use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection strings, such as the MSSQL service account password using aspnet_regiis command.

## References
https://www.elastic.co/guide/en/security/current/microsoft-iis-connection-strings-decryption.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "connectionStrings" AND TgtProcCmdLine containsCIS " -pdf") AND TgtProcImagePath endswithCIS "\aspnet_regiis.exe"))

```