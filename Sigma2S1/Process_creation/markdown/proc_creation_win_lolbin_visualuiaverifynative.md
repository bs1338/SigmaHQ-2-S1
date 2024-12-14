# proc_creation_win_lolbin_visualuiaverifynative

## Title
Use of VisualUiaVerifyNative.exe

## ID
b30a8bc5-e21b-4ca2-9420-0a94019ac56a

## Author
Christopher Peacock @SecurePeacock, SCYTHE @scythe_io

## Date
2022-06-01

## Tags
attack.defense-evasion, attack.t1218

## Description
VisualUiaVerifyNative.exe is a Windows SDK that can be used for AWL bypass and is listed in Microsoft's recommended block rules.

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/VisualUiaVerifyNative/
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac
https://bohops.com/2020/10/15/exploring-the-wdac-microsoft-recommended-block-rules-visualuiaverifynative/
https://github.com/MicrosoftDocs/windows-itpro-docs/commit/937db704b9148e9cee7c7010cad4d00ce9c4fdad

## False Positives
Legitimate testing of Microsoft UI parts.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\VisualUiaVerifyNative.exe")

```