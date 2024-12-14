# registry_delete_removal_com_hijacking_registry_key

## Title
Removal of Potential COM Hijacking Registry Keys

## ID
96f697b0-b499-4e5d-9908-a67bec11cdb6

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-05-02

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects any deletion of entries in ".*\shell\open\command" registry keys.
These registry keys might have been used for COM hijacking activities by a threat actor or an attacker and the deletion could indicate steps to remove its tracks.


## References
https://github.com/OTRF/detection-hackathon-apt29/issues/7
https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.C.1_22A46621-7A92-48C1-81BF-B3937EB4FDC3.md
https://learn.microsoft.com/en-us/windows/win32/shell/launch
https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexecutecommand
https://learn.microsoft.com/en-us/windows/win32/shell/shell-and-managed-code

## False Positives
Legitimate software (un)installations are known to cause some false positives. Please add them as a filter when encountered

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "DeleteKey" AND RegistryKeyPath endswithCIS "\shell\open\command") AND (NOT ((SrcProcImagePath endswithCIS "\Dropbox.exe" AND RegistryKeyPath containsCIS "\Dropbox.") OR (SrcProcImagePath endswithCIS "\Everything.exe" AND RegistryKeyPath containsCIS "\Everything.") OR SrcProcImagePath = "C:\Program Files (x86)\Microsoft Office\root\integration\integrator.exe" OR (SrcProcImagePath endswithCIS "\installer.exe" AND SrcProcImagePath startswithCIS "C:\Program Files (x86)\Java\" AND RegistryKeyPath containsCIS "\Classes\WOW6432Node\CLSID\{4299124F-F2C3-41b4-9C73-9236B2AD0E8F}") OR (SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\" OR SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Updates\")) OR (SrcProcImagePath endswithCIS "\installer.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Opera\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Opera\")) OR (SrcProcImagePath containsCIS "peazip" AND RegistryKeyPath containsCIS "\PeaZip.") OR SrcProcImagePath = "C:\Windows\system32\svchost.exe" OR SrcProcImagePath startswithCIS "C:\Windows\Installer\MSI" OR (SrcProcImagePath endswithCIS "\AppData\Local\Temp\Wireshark_uninstaller.exe" AND RegistryKeyPath containsCIS "\wireshark-capture-file\")))))

```