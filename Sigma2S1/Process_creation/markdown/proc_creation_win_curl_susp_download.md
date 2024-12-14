# proc_creation_win_curl_susp_download

## Title
Suspicious Curl.EXE Download

## ID
e218595b-bbe7-4ee5-8a96-f32a24ad3468

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2020-07-03

## Tags
attack.command-and-control, attack.t1105

## Description
Detects a suspicious curl process start on Windows and outputs the requested document to a local file

## References
https://twitter.com/max_mal_/status/1542461200797163522
https://web.archive.org/web/20200128160046/https://twitter.com/reegun21/status/1222093798009790464
https://github.com/pr0xylife/Qakbot/blob/4f0795d79dabee5bc9dd69f17a626b48852e7869/Qakbot_AA_23.06.2022.txt
https://www.volexity.com/blog/2022/07/28/sharptongue-deploys-clever-mail-stealing-browser-extension-sharpext/
https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1105/T1105.md#atomic-test-18---curl-download-file

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcDisplayName = "The curl executable") AND ((TgtProcCmdLine endswithCIS ".dll" OR TgtProcCmdLine endswithCIS ".gif" OR TgtProcCmdLine endswithCIS ".jpeg" OR TgtProcCmdLine endswithCIS ".jpg" OR TgtProcCmdLine endswithCIS ".png" OR TgtProcCmdLine endswithCIS ".temp" OR TgtProcCmdLine endswithCIS ".tmp" OR TgtProcCmdLine endswithCIS ".txt" OR TgtProcCmdLine endswithCIS ".vbe" OR TgtProcCmdLine endswithCIS ".vbs") OR (TgtProcCmdLine containsCIS "%AppData%" OR TgtProcCmdLine containsCIS "%Public%" OR TgtProcCmdLine containsCIS "%Temp%" OR TgtProcCmdLine containsCIS "%tmp%" OR TgtProcCmdLine containsCIS "\AppData\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Temp\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "C:\PerfLogs\" OR TgtProcCmdLine containsCIS "C:\ProgramData\" OR TgtProcCmdLine containsCIS "C:\Windows\Temp\")) AND (NOT ((TgtProcCmdLine containsCIS "--silent --show-error --output " AND TgtProcCmdLine containsCIS "gfw-httpget-" AND TgtProcCmdLine containsCIS "AppData") AND TgtProcImagePath = "C:\Program Files\Git\mingw64\bin\curl.exe" AND SrcProcImagePath = "C:\Program Files\Git\usr\bin\sh.exe"))))

```