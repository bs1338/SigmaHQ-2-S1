# proc_creation_win_wab_unusual_parents

## Title
Wab/Wabmig Unusual Parent Or Child Processes

## ID
63d1ccc0-2a43-4f4b-9289-361b308991ff

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-12

## Tags
attack.defense-evasion, attack.execution

## Description
Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity

## References
https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bumblebee-loader-cybercrime
https://thedfirreport.com/2022/09/26/bumblebee-round-two/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\wab.exe" OR SrcProcImagePath endswithCIS "\wabmig.exe") OR ((TgtProcImagePath endswithCIS "\wab.exe" OR TgtProcImagePath endswithCIS "\wabmig.exe") AND (SrcProcImagePath endswithCIS "\WmiPrvSE.exe" OR SrcProcImagePath endswithCIS "\svchost.exe" OR SrcProcImagePath endswithCIS "\dllhost.exe"))))

```