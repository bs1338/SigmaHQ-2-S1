# proc_creation_win_powershell_susp_ps_downloadfile

## Title
PowerShell DownloadFile

## ID
8f70ac5f-1f6f-4f8e-b454-db19561216c5

## Author
Florian Roth (Nextron Systems)

## Date
2020-08-28

## Tags
attack.execution, attack.t1059.001, attack.command-and-control, attack.t1104, attack.t1105

## Description
Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line

## References
https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "powershell" AND TgtProcCmdLine containsCIS ".DownloadFile" AND TgtProcCmdLine containsCIS "System.Net.WebClient"))

```