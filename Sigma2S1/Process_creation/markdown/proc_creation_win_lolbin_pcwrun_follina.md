# proc_creation_win_lolbin_pcwrun_follina

## Title
Execute Pcwrun.EXE To Leverage Follina

## ID
6004abd0-afa4-4557-ba90-49d172e0a299

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-13

## Tags
attack.defense-evasion, attack.t1218, attack.execution

## Description
Detects indirect command execution via Program Compatibility Assistant "pcwrun.exe" leveraging the follina (CVE-2022-30190) vulnerability

## References
https://twitter.com/nas_bench/status/1535663791362519040

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "../" AND TgtProcImagePath endswithCIS "\pcwrun.exe"))

```