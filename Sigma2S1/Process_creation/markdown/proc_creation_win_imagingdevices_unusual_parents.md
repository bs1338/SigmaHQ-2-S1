# proc_creation_win_imagingdevices_unusual_parents

## Title
ImagingDevices Unusual Parent/Child Processes

## ID
f11f2808-adb4-46c0-802a-8660db50fa99

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-27

## Tags
attack.defense-evasion, attack.execution

## Description
Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity

## References
https://thedfirreport.com/2022/09/26/bumblebee-round-two/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\ImagingDevices.exe" OR (TgtProcImagePath endswithCIS "\ImagingDevices.exe" AND (SrcProcImagePath endswithCIS "\WmiPrvSE.exe" OR SrcProcImagePath endswithCIS "\svchost.exe" OR SrcProcImagePath endswithCIS "\dllhost.exe"))))

```