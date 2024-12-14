# proc_creation_win_gfxdownloadwrapper_arbitrary_file_download

## Title
Arbitrary File Download Via GfxDownloadWrapper.EXE

## ID
eee00933-a761-4cd0-be70-c42fe91731e7

## Author
Victor Sergeev, oscd.community

## Date
2020-10-09

## Tags
attack.command-and-control, attack.t1105

## Description
Detects execution of GfxDownloadWrapper.exe with a URL as an argument to download file.

## References
https://lolbas-project.github.io/lolbas/HonorableMentions/GfxDownloadWrapper/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\GfxDownloadWrapper.exe") AND (NOT TgtProcCmdLine containsCIS "https://gameplayapi.intel.com/")))

```