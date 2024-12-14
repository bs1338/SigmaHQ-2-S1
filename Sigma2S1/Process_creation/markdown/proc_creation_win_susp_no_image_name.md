# proc_creation_win_susp_no_image_name

## Title
Process Launched Without Image Name

## ID
f208d6d8-d83a-4c2c-960d-877c37da84e5

## Author
Matt Anderson (Huntress)

## Date
2024-07-23

## Tags
attack.defense-evasion

## Description
Detect the use of processes with no name (".exe"), which can be used to evade Image-based detections.

## References
https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software

## False Positives
Rare legitimate software.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\.exe")

```