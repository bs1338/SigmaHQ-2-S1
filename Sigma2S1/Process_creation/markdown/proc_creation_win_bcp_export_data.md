# proc_creation_win_bcp_export_data

## Title
Data Export From MSSQL Table Via BCP.EXE

## ID
c615d676-f655-46b9-b913-78729021e5d7

## Author
Omar Khaled (@beacon_exe), MahirAli Khan (in/mahiralikhan), Nasreddine Bencherchali (Nextron Systems)

## Date
2024-08-20

## Tags
attack.execution, attack.t1048

## Description
Detects the execution of the BCP utility in order to export data from the database.
Attackers were seen saving their malware to a database column or table and then later extracting it via "bcp.exe" into a file.


## References
https://docs.microsoft.com/en-us/sql/tools/bcp-utility
https://asec.ahnlab.com/en/61000/
https://asec.ahnlab.com/en/78944/
https://www.huntress.com/blog/attacking-mssql-servers
https://www.huntress.com/blog/attacking-mssql-servers-pt-ii
https://news.sophos.com/en-us/2024/08/07/sophos-mdr-hunt-tracks-mimic-ransomware-campaign-against-organizations-in-india/
https://research.nccgroup.com/2018/03/10/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/

## False Positives
Legitimate data export operations.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " out " OR TgtProcCmdLine containsCIS " queryout ") AND TgtProcImagePath endswithCIS "\bcp.exe"))

```