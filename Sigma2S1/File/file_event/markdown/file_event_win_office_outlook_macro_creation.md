# file_event_win_office_outlook_macro_creation

## Title
New Outlook Macro Created

## ID
8c31f563-f9a7-450c-bfa8-35f8f32f1f61

## Author
@ScoubiMtl

## Date
2021-04-05

## Tags
attack.persistence, attack.command-and-control, attack.t1137, attack.t1008, attack.t1546

## Description
Detects the creation of a macro file for Outlook.

## References
https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/

## False Positives
User genuinely creates a VB Macro for their email

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\outlook.exe" AND TgtFilePath endswithCIS "\Microsoft\Outlook\VbaProject.OTM"))

```