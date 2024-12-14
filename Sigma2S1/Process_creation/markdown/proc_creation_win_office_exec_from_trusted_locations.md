# proc_creation_win_office_exec_from_trusted_locations

## Title
Potentially Suspicious Office Document Executed From Trusted Location

## ID
f99abdf0-6283-4e71-bd2b-b5c048a94743

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-21

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects the execution of an Office application that points to a document that is located in a trusted location. Attackers often used this to avoid macro security and execute their malicious code.

## References
Internal Research
https://twitter.com/Max_Mal_/status/1633863678909874176
https://techcommunity.microsoft.com/t5/microsoft-365-blog/new-security-hardening-policies-for-trusted-documents/ba-p/3023465
https://twitter.com/_JohnHammond/status/1588155401752788994

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\EXCEL.EXE" OR TgtProcImagePath endswithCIS "\POWERPNT.EXE" OR TgtProcImagePath endswithCIS "\WINWORD.exe") AND (SrcProcImagePath endswithCIS "\explorer.exe" OR SrcProcImagePath endswithCIS "\dopus.exe") AND (TgtProcCmdLine containsCIS "\AppData\Roaming\Microsoft\Templates" OR TgtProcCmdLine containsCIS "\AppData\Roaming\Microsoft\Word\Startup\" OR TgtProcCmdLine containsCIS "\Microsoft Office\root\Templates\" OR TgtProcCmdLine containsCIS "\Microsoft Office\Templates\")) AND (NOT (TgtProcCmdLine endswithCIS ".dotx" OR TgtProcCmdLine endswithCIS ".xltx" OR TgtProcCmdLine endswithCIS ".potx"))))

```