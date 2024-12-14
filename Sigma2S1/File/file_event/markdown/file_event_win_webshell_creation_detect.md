# file_event_win_webshell_creation_detect

## Title
Potential Webshell Creation On Static Website

## ID
39f1f9f2-9636-45de-98f6-a4046aa8e4b9

## Author
Beyu Denis, oscd.community, Tim Shelton, Thurein Oo

## Date
2019-10-22

## Tags
attack.persistence, attack.t1505.003

## Description
Detects the creation of files with certain extensions on a static web site. This can be indicative of potential uploads of a web shell.

## References
PT ESC rule and personal experience
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/c95a0a1a2855dc0cd7f7327614545fe30482a636/Upload%20Insecure%20Files/README.md

## False Positives
Legitimate administrator or developer creating legitimate executable files in a web application folder

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((((TgtFilePath containsCIS ".ashx" OR TgtFilePath containsCIS ".asp" OR TgtFilePath containsCIS ".ph" OR TgtFilePath containsCIS ".soap") AND TgtFilePath containsCIS "\inetpub\wwwroot\") OR (TgtFilePath containsCIS ".ph" AND (TgtFilePath containsCIS "\www\" OR TgtFilePath containsCIS "\htdocs\" OR TgtFilePath containsCIS "\html\"))) AND (NOT (TgtFilePath containsCIS "\xampp" OR SrcProcImagePath = "System" OR (TgtFilePath containsCIS "\AppData\Local\Temp\" OR TgtFilePath containsCIS "\Windows\Temp\")))))

```