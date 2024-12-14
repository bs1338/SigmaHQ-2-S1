# file_event_win_startup_folder_file_write

## Title
Startup Folder File Write

## ID
2aa0a6b4-a865-495b-ab51-c28249537b75

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-05-02

## Tags
attack.persistence, attack.t1547.001

## Description
A General detection for files being created in the Windows startup directory. This could be an indicator of persistence.

## References
https://github.com/OTRF/detection-hackathon-apt29/issues/12
https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/5.B.1_611FCA99-97D0-4873-9E51-1C1BA2DBB40D.md

## False Positives
FP could be caused by legitimate application writing shortcuts for example. This folder should always be inspected to make sure that all the files in there are legitimate

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "\Microsoft\Windows\Start Menu\Programs\StartUp" AND (NOT (SrcProcImagePath = "C:\Windows\System32\wuauclt.exe" OR TgtFilePath startswithCIS "C:\$WINDOWS.~BT\NewOS\"))))

```