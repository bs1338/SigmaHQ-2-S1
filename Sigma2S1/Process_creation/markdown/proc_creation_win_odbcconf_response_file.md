# proc_creation_win_odbcconf_response_file

## Title
Response File Execution Via Odbcconf.EXE

## ID
5f03babb-12db-4eec-8c82-7b4cb5580868

## Author
Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-22

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects execution of "odbcconf" with the "-f" flag in order to load a response file which might contain a malicious action.

## References
https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
https://www.cybereason.com/blog/threat-analysis-report-bumblebee-loader-the-high-road-to-enterprise-domain-control
https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/

## False Positives
The rule is looking for any usage of response file, which might generate false positive when this function is used legitimately. Investigate the contents of the ".rsp" file to determine if it is malicious and apply additional filters if necessary.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -f " OR TgtProcCmdLine containsCIS " /f " OR TgtProcCmdLine containsCIS " â€“f " OR TgtProcCmdLine containsCIS " â€”f " OR TgtProcCmdLine containsCIS " â€•f ") AND TgtProcImagePath endswithCIS "\odbcconf.exe" AND TgtProcCmdLine containsCIS ".rsp"))

```