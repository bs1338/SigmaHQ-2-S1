# proc_creation_win_powershell_download_cradle_obfuscated

## Title
Obfuscated PowerShell OneLiner Execution

## ID
44e24481-6202-4c62-9127-5a0ae8e3fe3d

## Author
@Kostastsale, @TheDFIRReport

## Date
2022-05-09

## Tags
attack.defense-evasion, attack.execution, attack.t1059.001, attack.t1562.001

## Description
Detects the execution of a specific OneLiner to download and execute powershell modules in memory.

## References
https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://127.0.0.1" AND TgtProcCmdLine containsCIS "%{(IRM $_)}" AND TgtProcCmdLine containsCIS ".SubString.ToString()[67,72,64]-Join" AND TgtProcCmdLine containsCIS "Import-Module") AND TgtProcImagePath endswithCIS "\powershell.exe"))

```