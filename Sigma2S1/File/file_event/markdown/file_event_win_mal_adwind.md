# file_event_win_mal_adwind

## Title
Adwind RAT / JRAT File Artifact

## ID
0bcfabcb-7929-47f4-93d6-b33fb67d34d1

## Author
Florian Roth (Nextron Systems), Tom Ueltschi, Jonhnathan Ribeiro, oscd.community

## Date
2017-11-10

## Tags
attack.execution, attack.t1059.005, attack.t1059.007

## Description
Detects javaw.exe in AppData folder as used by Adwind / JRAT

## References
https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf

## False Positives


## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\AppData\Roaming\Oracle\bin\java" AND TgtFilePath containsCIS ".exe") OR (TgtFilePath containsCIS "\Retrive" AND TgtFilePath containsCIS ".vbs")))

```