# proc_creation_win_powershell_defender_exclusion

## Title
Powershell Defender Exclusion

## ID
17769c90-230e-488b-a463-e05c08e9d48f

## Author
Florian Roth (Nextron Systems)

## Date
2021-04-29

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets

## References
https://learn.microsoft.com/en-us/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
https://twitter.com/AdamTheAnalyst/status/1483497517119590403

## False Positives
Possible Admin Activity
Other Cmdlets that may use the same parameters

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Add-MpPreference " OR TgtProcCmdLine containsCIS "Set-MpPreference ") AND (TgtProcCmdLine containsCIS " -ExclusionPath " OR TgtProcCmdLine containsCIS " -ExclusionExtension " OR TgtProcCmdLine containsCIS " -ExclusionProcess " OR TgtProcCmdLine containsCIS " -ExclusionIpAddress ")))

```