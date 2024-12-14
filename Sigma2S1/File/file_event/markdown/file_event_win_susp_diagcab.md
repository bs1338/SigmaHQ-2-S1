# file_event_win_susp_diagcab

## Title
Creation of a Diagcab

## ID
3d0ed417-3d94-4963-a562-4a92c940656a

## Author
frack113

## Date
2022-06-08

## Tags
attack.resource-development

## Description
Detects the creation of diagcab file, which could be caused by some legitimate installer or is a sign of exploitation (review the filename and its location)

## References
https://threadreaderapp.com/thread/1533879688141086720.html

## False Positives
Legitimate microsoft diagcab

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS ".diagcab")

```