# proc_creation_win_webshell_hacking

## Title
Webshell Hacking Activity Patterns

## ID
4ebc877f-4612-45cb-b3a5-8e3834db36c9

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-17

## Tags
attack.persistence, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087

## Description
Detects certain parent child patterns found in cases in which a web shell is used to perform certain credential dumping or exfiltration activities on a compromised system


## References
https://youtu.be/7aemGhaE9ds?t=641

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((SrcProcImagePath containsCIS "-tomcat-" OR SrcProcImagePath containsCIS "\tomcat") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR ((TgtProcCmdLine containsCIS "catalina.jar" OR TgtProcCmdLine containsCIS "CATALINA_HOME") AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")) OR (SrcProcImagePath endswithCIS "\caddy.exe" OR SrcProcImagePath endswithCIS "\httpd.exe" OR SrcProcImagePath endswithCIS "\nginx.exe" OR SrcProcImagePath endswithCIS "\php-cgi.exe" OR SrcProcImagePath endswithCIS "\w3wp.exe" OR SrcProcImagePath endswithCIS "\ws_tomcatservice.exe")) AND ((TgtProcCmdLine containsCIS "rundll32" AND TgtProcCmdLine containsCIS "comsvcs") OR (TgtProcCmdLine containsCIS " -hp" AND TgtProcCmdLine containsCIS " a " AND TgtProcCmdLine containsCIS " -m") OR (TgtProcCmdLine containsCIS "net" AND TgtProcCmdLine containsCIS " user " AND TgtProcCmdLine containsCIS " /add") OR (TgtProcCmdLine containsCIS "net" AND TgtProcCmdLine containsCIS " localgroup " AND TgtProcCmdLine containsCIS " administrators " AND TgtProcCmdLine containsCIS "/add") OR (TgtProcImagePath endswithCIS "\ntdsutil.exe" OR TgtProcImagePath endswithCIS "\ldifde.exe" OR TgtProcImagePath endswithCIS "\adfind.exe" OR TgtProcImagePath endswithCIS "\procdump.exe" OR TgtProcImagePath endswithCIS "\Nanodump.exe" OR TgtProcImagePath endswithCIS "\vssadmin.exe" OR TgtProcImagePath endswithCIS "\fsutil.exe") OR (TgtProcCmdLine containsCIS " -decode " OR TgtProcCmdLine containsCIS " -NoP " OR TgtProcCmdLine containsCIS " -W Hidden " OR TgtProcCmdLine containsCIS " /decode " OR TgtProcCmdLine containsCIS " /ticket:" OR TgtProcCmdLine containsCIS " sekurlsa" OR TgtProcCmdLine containsCIS ".dmp full" OR TgtProcCmdLine containsCIS ".downloadfile(" OR TgtProcCmdLine containsCIS ".downloadstring(" OR TgtProcCmdLine containsCIS "FromBase64String" OR TgtProcCmdLine containsCIS "process call create" OR TgtProcCmdLine containsCIS "reg save " OR TgtProcCmdLine containsCIS "whoami /priv"))))

```