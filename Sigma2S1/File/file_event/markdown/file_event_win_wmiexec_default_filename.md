# file_event_win_wmiexec_default_filename

## Title
Wmiexec Default Output File

## ID
8d5aca11-22b3-4f22-b7ba-90e60533e1fb

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-02

## Tags
attack.lateral-movement, attack.t1047

## Description
Detects the creation of the default output filename used by the wmiexec tool

## References
https://www.crowdstrike.com/blog/how-to-detect-and-prevent-impackets-wmiexec/
https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/examples/wmiexec.py

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath RegExp "\\\\Windows\\\\__1\\d{9}\\.\\d{1,7}$" OR TgtFilePath RegExp "C:\\\\__1\\d{9}\\.\\d{1,7}$" OR TgtFilePath RegExp "D:\\\\__1\\d{9}\\.\\d{1,7}$"))

```