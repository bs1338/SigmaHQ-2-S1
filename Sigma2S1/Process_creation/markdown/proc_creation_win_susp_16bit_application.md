# proc_creation_win_susp_16bit_application

## Title
Start of NT Virtual DOS Machine

## ID
16905e21-66ee-42fe-b256-1318ada2d770

## Author
frack113

## Date
2022-07-16

## Tags
attack.defense-evasion

## Description
Ntvdm.exe allows the execution of 16-bit Windows applications on 32-bit Windows operating systems, as well as the execution of both 16-bit and 32-bit DOS applications

## References
https://learn.microsoft.com/en-us/windows/compatibility/ntvdm-and-16-bit-app-support
https://support.microsoft.com/fr-fr/topic/an-ms-dos-based-program-that-uses-the-ms-dos-protected-mode-interface-crashes-on-a-computer-that-is-running-windows-7-5dc739ea-987b-b458-15e4-d28d5cca63c7
https://app.any.run/tasks/93fe92fa-8b2b-4d92-8c09-a841aed2e793/
https://app.any.run/tasks/214094a7-0abc-4a7b-a564-1b757faed79d/

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\ntvdm.exe" OR TgtProcImagePath endswithCIS "\csrstub.exe"))

```