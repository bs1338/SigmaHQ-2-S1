# proc_creation_win_iis_appcmd_service_account_password_dumped

## Title
Microsoft IIS Service Account Password Dumped

## ID
2d3cdeec-c0db-45b4-aa86-082f7eb75701

## Author
Tim Rauch, Janantha Marasinghe, Elastic (original idea)

## Date
2022-11-08

## Tags
attack.credential-access, attack.t1003

## Description
Detects the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords

## References
https://www.elastic.co/guide/en/security/current/microsoft-iis-service-account-password-dumped.html
https://twitter.com/0gtweet/status/1588815661085917186?cxt=HHwWhIDUyaDbzYwsAAAA
https://www.netspi.com/blog/technical/network-penetration-testing/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "list " AND TgtProcImagePath endswithCIS "\appcmd.exe") AND ((TgtProcCmdLine containsCIS " /config" OR TgtProcCmdLine containsCIS " /xml" OR TgtProcCmdLine containsCIS " -config" OR TgtProcCmdLine containsCIS " -xml") OR ((TgtProcCmdLine containsCIS " /@t" OR TgtProcCmdLine containsCIS " /text" OR TgtProcCmdLine containsCIS " /show" OR TgtProcCmdLine containsCIS " -@t" OR TgtProcCmdLine containsCIS " -text" OR TgtProcCmdLine containsCIS " -show") AND (TgtProcCmdLine containsCIS ":\*" OR TgtProcCmdLine containsCIS "password")))))

```