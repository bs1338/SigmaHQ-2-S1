# proc_creation_win_powershell_base64_encoded_cmd_patterns

## Title
Suspicious PowerShell Encoded Command Patterns

## ID
b9d9cc83-380b-4ba3-8d8f-60c0e7e2930c

## Author
Florian Roth (Nextron Systems)

## Date
2022-05-24

## Tags
attack.execution, attack.t1059.001

## Description
Detects PowerShell command line patterns in combincation with encoded commands that often appear in malware infection chains

## References
https://app.any.run/tasks/b9040c63-c140-479b-ad59-f1bb56ce7a97/

## False Positives
Other tools that work with encoded scripts in the command line instead of script files

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " JAB" OR TgtProcCmdLine containsCIS " SUVYI" OR TgtProcCmdLine containsCIS " SQBFAFgA" OR TgtProcCmdLine containsCIS " aWV4I" OR TgtProcCmdLine containsCIS " IAB" OR TgtProcCmdLine containsCIS " PAA" OR TgtProcCmdLine containsCIS " aQBlAHgA") AND (TgtProcCmdLine containsCIS " -e " OR TgtProcCmdLine containsCIS " -en " OR TgtProcCmdLine containsCIS " -enc " OR TgtProcCmdLine containsCIS " -enco") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) AND (NOT (SrcProcImagePath containsCIS "C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\" OR SrcProcImagePath containsCIS "\gc_worker.exe"))))

```