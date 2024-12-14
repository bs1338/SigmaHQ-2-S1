# proc_creation_win_cmd_http_appdata

## Title
Command Line Execution with Suspicious URL and AppData Strings

## ID
1ac8666b-046f-4201-8aba-1951aaec03a3

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community

## Date
2019-01-16

## Tags
attack.execution, attack.command-and-control, attack.t1059.003, attack.t1059.001, attack.t1105

## Description
Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)

## References
https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100
https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100

## False Positives
High

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http" AND TgtProcCmdLine containsCIS "://" AND TgtProcCmdLine containsCIS "%AppData%") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```