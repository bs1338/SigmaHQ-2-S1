# proc_creation_win_csc_susp_parent

## Title
Csc.EXE Execution Form Potentially Suspicious Parent

## ID
b730a276-6b63-41b8-bcf8-55930c8fc6ee

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)

## Date
2019-02-11

## Tags
attack.execution, attack.t1059.005, attack.t1059.007, attack.defense-evasion, attack.t1218.005, attack.t1027.004

## Description
Detects a potentially suspicious parent of "csc.exe", which could be a sign of payload delivery.

## References
https://www.uptycs.com/blog/warzonerat-can-now-evade-with-process-hollowing
https://reaqta.com/2017/11/short-journey-darkvnc/
https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\csc.exe" AND ((SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\excel.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\onenote.exe" OR SrcProcImagePath endswithCIS "\outlook.exe" OR SrcProcImagePath endswithCIS "\powerpnt.exe" OR SrcProcImagePath endswithCIS "\winword.exe" OR SrcProcImagePath endswithCIS "\wscript.exe") OR ((SrcProcCmdLine containsCIS "-Encoded " OR SrcProcCmdLine containsCIS "FromBase64String") AND (SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe")) OR (SrcProcCmdLine RegExp "([Pp]rogram[Dd]ata|%([Ll]ocal)?[Aa]pp[Dd]ata%|\\\\[Aa]pp[Dd]ata\\\\([Ll]ocal([Ll]ow)?|[Rr]oaming))\\\\[^\\\\]{1,256}$" OR (SrcProcCmdLine containsCIS ":\PerfLogs\" OR SrcProcCmdLine containsCIS ":\Users\Public\" OR SrcProcCmdLine containsCIS ":\Windows\Temp\" OR SrcProcCmdLine containsCIS "\Temporary Internet") OR (SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\Favorites\") OR (SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\Favourites\") OR (SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\Contacts\") OR (SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\Pictures\"))) AND (NOT ((SrcProcImagePath startswithCIS "C:\Program Files (x86)\" OR SrcProcImagePath startswithCIS "C:\Program Files\") OR SrcProcImagePath = "C:\Windows\System32\sdiagnhost.exe" OR SrcProcImagePath = "C:\Windows\System32\inetsrv\w3wp.exe")) AND (NOT ((SrcProcCmdLine containsCIS "JwB7ACIAZgBhAGkAbABlAGQAIgA6AHQAcgB1AGUALAAiAG0AcwBnACIAOgAiAEEAbgBzAGkAYgBsAGUAIAByAGUAcQB1AGkAcgBlAHMAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAdgAzAC4AMAAgAG8AcgAgAG4AZQB3AGUAcgAiAH0AJw" OR SrcProcCmdLine containsCIS "cAewAiAGYAYQBpAGwAZQBkACIAOgB0AHIAdQBlACwAIgBtAHMAZwAiADoAIgBBAG4AcwBpAGIAbABlACAAcgBlAHEAdQBpAHIAZQBzACAAUABvAHcAZQByAFMAaABlAGwAbAAgAHYAMwAuADAAIABvAHIAIABuAGUAdwBlAHIAIgB9ACcA" OR SrcProcCmdLine containsCIS "nAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnA") OR SrcProcImagePath = "C:\ProgramData\chocolatey\choco.exe" OR SrcProcCmdLine containsCIS "\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"))))

```