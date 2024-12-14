# file_event_win_susp_teamviewer_remote_session

## Title
TeamViewer Remote Session

## ID
162ab1e4-6874-4564-853c-53ec3ab8be01

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-30

## Tags
attack.command-and-control, attack.t1219

## Description
Detects the creation of log files during a TeamViewer remote session

## References
https://www.teamviewer.com/en-us/

## False Positives
Legitimate uses of TeamViewer in an organisation

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\TeamViewer\RemotePrinting\tvprint.db" OR TgtFilePath endswithCIS "\TeamViewer\TVNetwork.log") OR (TgtFilePath containsCIS "\TeamViewer" AND TgtFilePath containsCIS "_Logfile.log")))

```