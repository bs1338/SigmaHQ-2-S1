# proc_creation_win_hh_susp_execution

## Title
Suspicious HH.EXE Execution

## ID
e8a95b5e-c891-46e2-b33a-93937d3abc31

## Author
Maxim Pavlunin

## Date
2020-04-01

## Tags
attack.defense-evasion, attack.execution, attack.initial-access, attack.t1047, attack.t1059.001, attack.t1059.003, attack.t1059.005, attack.t1059.007, attack.t1218, attack.t1218.001, attack.t1218.010, attack.t1218.011, attack.t1566, attack.t1566.001

## Description
Detects a suspicious execution of a Microsoft HTML Help (HH.exe)

## References
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/
https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-27939090904026cc396b0b629c8e4314acd6f5dac40a676edbc87f4567b47eb7
https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\hh.exe" AND (TgtProcCmdLine containsCIS ".application" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\Content.Outlook\" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\Windows\Temp\")))

```