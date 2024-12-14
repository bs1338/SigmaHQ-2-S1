# proc_creation_win_powershell_download_patterns

## Title
PowerShell Download Pattern

## ID
3b6ab547-8ec2-4991-b9d2-2b06702a48d7

## Author
Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro

## Date
2019-01-16

## Tags
attack.execution, attack.t1059.001

## Description
Detects a Powershell process that contains download commands in its command line string

## References
https://blog.redteam.pl/2020/06/black-kingdom-ransomware.html
https://lab52.io/blog/winter-vivern-all-summer/
https://hatching.io/blog/powershell-analysis/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "string(" OR TgtProcCmdLine containsCIS "file(") AND (TgtProcCmdLine containsCIS "new-object" AND TgtProcCmdLine containsCIS "net.webclient)." AND TgtProcCmdLine containsCIS "download")) AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```