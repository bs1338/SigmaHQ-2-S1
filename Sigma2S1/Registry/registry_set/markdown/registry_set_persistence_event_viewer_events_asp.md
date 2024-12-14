# registry_set_persistence_event_viewer_events_asp

## Title
Potential Persistence Via Event Viewer Events.asp

## ID
a1e11042-a74a-46e6-b07c-c4ce8ecc239b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-17

## Tags
attack.persistence, attack.defense-evasion, attack.t1112

## Description
Detects potential registry persistence technique using the Event Viewer "Events.asp" technique

## References
https://twitter.com/nas_bench/status/1626648985824788480
https://admx.help/?Category=Windows_7_2008R2&Policy=Microsoft.Policies.InternetCommunicationManagement::EventViewer_DisableLinks
https://www.hexacorn.com/blog/2019/02/15/beyond-good-ol-run-key-part-103/
https://github.com/redcanaryco/atomic-red-team/blob/f296668303c29d3f4c07e42bdd2b28d8dd6625f9/atomics/T1112/T1112.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\Event Viewer\MicrosoftRedirectionProgram" OR RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\Event Viewer\MicrosoftRedirectionURL") AND (NOT (RegistryValue = "(Empty)" OR (RegistryValue = "%%SystemRoot%%\PCHealth\HelpCtr\Binaries\HelpCtr.exe" AND SrcProcImagePath endswithCIS "C:\WINDOWS\system32\svchost.exe" AND RegistryKeyPath endswithCIS "\Microsoft\Windows NT\CurrentVersion\Event Viewer\MicrosoftRedirectionProgram") OR (RegistryValue = "-url hcp://services/centers/support*topic=%%s" AND SrcProcImagePath endswithCIS "C:\WINDOWS\system32\svchost.exe" AND RegistryKeyPath endswithCIS "\Microsoft\Windows NT\CurrentVersion\Event Viewer\MicrosoftRedirectionProgramCommandLineParameters") OR RegistryValue = "http://go.microsoft.com/fwlink/events.asp"))))

```