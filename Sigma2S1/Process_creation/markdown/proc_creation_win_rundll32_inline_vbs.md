# proc_creation_win_rundll32_inline_vbs

## Title
Suspicious Rundll32 Invoking Inline VBScript

## ID
1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd

## Author
Florian Roth (Nextron Systems)

## Date
2021-03-05

## Tags
attack.defense-evasion, attack.t1055

## Description
Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452

## References
https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "rundll32.exe" AND TgtProcCmdLine containsCIS "Execute" AND TgtProcCmdLine containsCIS "RegRead" AND TgtProcCmdLine containsCIS "window.close"))

```