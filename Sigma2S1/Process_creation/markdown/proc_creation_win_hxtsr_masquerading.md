# proc_creation_win_hxtsr_masquerading

## Title
Potential Fake Instance Of Hxtsr.EXE Executed

## ID
4e762605-34a8-406d-b72e-c1a089313320

## Author
Sreeman

## Date
2020-04-17

## Tags
attack.defense-evasion, attack.t1036

## Description
HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.
HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files".
Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe


## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\hxtsr.exe" AND (NOT (TgtProcImagePath containsCIS ":\program files\windowsapps\microsoft.windowscommunicationsapps_" AND TgtProcImagePath endswithCIS "\hxtsr.exe"))))

```