# proc_creation_win_certutil_export_pfx

## Title
Certificate Exported Via Certutil.EXE

## ID
3ffd6f51-e6c1-47b7-94b4-c1e61d4117c5

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of the certutil with the "exportPFX" flag which allows the utility to export certificates.

## References
https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html

## False Positives
There legitimate reasons to export certificates. Investigate the activity to determine if it's benign

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-exportPFX " OR TgtProcCmdLine containsCIS "/exportPFX " OR TgtProcCmdLine containsCIS "â€“exportPFX " OR TgtProcCmdLine containsCIS "â€”exportPFX " OR TgtProcCmdLine containsCIS "â€•exportPFX ") AND TgtProcImagePath endswithCIS "\certutil.exe"))

```