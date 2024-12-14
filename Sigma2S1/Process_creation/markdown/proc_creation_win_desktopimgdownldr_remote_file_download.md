# proc_creation_win_desktopimgdownldr_remote_file_download

## Title
Remote File Download Via Desktopimgdownldr Utility

## ID
214641c2-c579-4ecb-8427-0cf19df6842e

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-27

## Tags
attack.command-and-control, attack.t1105

## Description
Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.

## References
https://www.elastic.co/guide/en/security/current/remote-file-download-via-desktopimgdownldr-utility.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/lockscreenurl:http" AND TgtProcImagePath endswithCIS "\desktopimgdownldr.exe" AND SrcProcImagePath endswithCIS "\desktopimgdownldr.exe"))

```