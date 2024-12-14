# proc_creation_win_cmd_type_arbitrary_file_download

## Title
Potential Download/Upload Activity Using Type Command

## ID
aa0b3a82-eacc-4ec3-9150-b5a9a3e3f82f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-14

## Tags
attack.command-and-control, attack.t1105

## Description
Detects usage of the "type" command to download/upload data from WebDAV server

## References
https://mr0range.com/a-new-lolbin-using-the-windows-type-command-to-upload-download-files-81d7b6179e22

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "type \\" AND TgtProcCmdLine containsCIS " > ") OR (TgtProcCmdLine containsCIS "type " AND TgtProcCmdLine containsCIS " > \\")))

```