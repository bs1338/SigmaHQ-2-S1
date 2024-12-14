# file_event_win_rclone_config_files

## Title
Rclone Config File Creation

## ID
34986307-b7f4-49be-92f3-e7a4d01ac5db

## Author
Aaron Greetham (@beardofbinary) - NCC Group

## Date
2021-05-26

## Tags
attack.exfiltration, attack.t1567.002

## Description
Detects Rclone config files being created

## References
https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/

## False Positives
Legitimate Rclone usage

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS ":\Users\" AND TgtFilePath containsCIS "\.config\rclone\"))

```