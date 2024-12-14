# proc_creation_win_chcp_codepage_switch

## Title
Suspicious CodePage Switch Via CHCP

## ID
c7942406-33dd-4377-a564-0f62db0593a3

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community

## Date
2019-10-14

## Tags
attack.t1036, attack.defense-evasion

## Description
Detects a code page switch in command line or batch scripts to a rare language

## References
https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
https://twitter.com/cglyer/status/1183756892952248325

## False Positives
Administrative activity (adjust code pages according to your organization's region)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS " 936" OR TgtProcCmdLine endswithCIS " 1258") AND TgtProcImagePath endswithCIS "\chcp.com"))

```