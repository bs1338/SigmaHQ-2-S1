# proc_creation_win_powershell_audio_capture

## Title
Audio Capture via PowerShell

## ID
932fb0d8-692b-4b0f-a26e-5643a50fe7d6

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-10-24

## Tags
attack.collection, attack.t1123

## Description
Detects audio capture via PowerShell Cmdlet.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1123/T1123.md
https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html
https://github.com/frgnca/AudioDeviceCmdlets

## False Positives
Legitimate audio capture by legitimate user.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "WindowsAudioDevice-Powershell-Cmdlet" OR TgtProcCmdLine containsCIS "Toggle-AudioDevice" OR TgtProcCmdLine containsCIS "Get-AudioDevice " OR TgtProcCmdLine containsCIS "Set-AudioDevice " OR TgtProcCmdLine containsCIS "Write-AudioDevice "))

```