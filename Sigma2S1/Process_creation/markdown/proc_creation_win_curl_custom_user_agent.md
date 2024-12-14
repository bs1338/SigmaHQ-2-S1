# proc_creation_win_curl_custom_user_agent

## Title
Curl Web Request With Potential Custom User-Agent

## ID
85de1f22-d189-44e4-8239-dc276b45379b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-27

## Tags
attack.execution

## Description
Detects execution of "curl.exe" with a potential custom "User-Agent". Attackers can leverage this to download or exfiltrate data via "curl" to a domain that only accept specific "User-Agent" strings

## References
https://labs.withsecure.com/publications/fin7-target-veeam-servers
https://github.com/WithSecureLabs/iocs/blob/344203de742bb7e68bd56618f66d34be95a9f9fc/FIN7VEEAM/iocs.csv

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "User-Agent:" AND TgtProcCmdLine RegExp "\\s-H\\s") AND TgtProcImagePath endswithCIS "\curl.exe"))

```