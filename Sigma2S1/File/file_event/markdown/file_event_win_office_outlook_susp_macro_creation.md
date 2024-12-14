# file_event_win_office_outlook_susp_macro_creation

## Title
Suspicious Outlook Macro Created

## ID
117d3d3a-755c-4a61-b23e-9171146d094c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-08

## Tags
attack.persistence, attack.command-and-control, attack.t1137, attack.t1008, attack.t1546

## Description
Detects the creation of a macro file for Outlook.

## References
https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53
https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\Microsoft\Outlook\VbaProject.OTM" AND (NOT SrcProcImagePath endswithCIS "\outlook.exe")))

```