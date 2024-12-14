# proc_creation_win_mstsc_run_local_rdp_file

## Title
Mstsc.EXE Execution With Local RDP File

## ID
5fdce3ac-e7f9-4ecd-a3aa-a4d78ebbf0af

## Author
Nasreddine Bencherchali (Nextron Systems), Christopher Peacock @securepeacock

## Date
2023-04-18

## Tags
attack.command-and-control, attack.t1219

## Description
Detects potential RDP connection via Mstsc using a local ".rdp" file

## References
https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/

## False Positives
Likely with legitimate usage of ".rdp" files

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine endswithCIS ".rdp" OR TgtProcCmdLine endswithCIS ".rdp\"") AND TgtProcImagePath endswithCIS "\mstsc.exe") AND (NOT (TgtProcCmdLine containsCIS "C:\ProgramData\Microsoft\WSL\wslg.rdp" AND SrcProcImagePath = "C:\Windows\System32\lxss\wslhost.exe"))))

```