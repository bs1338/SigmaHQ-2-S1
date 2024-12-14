# proc_creation_win_findstr_security_keyword_lookup

## Title
Security Tools Keyword Lookup Via Findstr.EXE

## ID
4fe074b4-b833-4081-8f24-7dcfeca72b42

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2023-10-20

## Tags
attack.discovery, attack.t1518.001

## Description
Detects execution of "findstr" to search for common names of security tools. Attackers often pipe the results of recon commands such as "tasklist" or "whoami" to "findstr" in order to filter out the results.
This detection focuses on the keywords that the attacker might use as a filter.


## References
https://github.com/redcanaryco/atomic-red-team/blob/987e3ca988ae3cff4b9f6e388c139c05bf44bbb8/atomics/T1518.001/T1518.001.md#atomic-test-1---security-software-discovery
https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/
https://www.hhs.gov/sites/default/files/manage-engine-vulnerability-sector-alert-tlpclear.pdf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS " avira" OR TgtProcCmdLine endswithCIS " avira\"" OR TgtProcCmdLine endswithCIS " cb" OR TgtProcCmdLine endswithCIS " cb\"" OR TgtProcCmdLine endswithCIS " cylance" OR TgtProcCmdLine endswithCIS " cylance\"" OR TgtProcCmdLine endswithCIS " defender" OR TgtProcCmdLine endswithCIS " defender\"" OR TgtProcCmdLine endswithCIS " kaspersky" OR TgtProcCmdLine endswithCIS " kaspersky\"" OR TgtProcCmdLine endswithCIS " kes" OR TgtProcCmdLine endswithCIS " kes\"" OR TgtProcCmdLine endswithCIS " mc" OR TgtProcCmdLine endswithCIS " mc\"" OR TgtProcCmdLine endswithCIS " sec" OR TgtProcCmdLine endswithCIS " sec\"" OR TgtProcCmdLine endswithCIS " sentinel" OR TgtProcCmdLine endswithCIS " sentinel\"" OR TgtProcCmdLine endswithCIS " symantec" OR TgtProcCmdLine endswithCIS " symantec\"" OR TgtProcCmdLine endswithCIS " virus" OR TgtProcCmdLine endswithCIS " virus\"") AND (TgtProcImagePath endswithCIS "\find.exe" OR TgtProcImagePath endswithCIS "\findstr.exe")))

```