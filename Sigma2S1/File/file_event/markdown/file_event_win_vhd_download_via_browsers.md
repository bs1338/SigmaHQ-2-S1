# file_event_win_vhd_download_via_browsers

## Title
VHD Image Download Via Browser

## ID
8468111a-ef07-4654-903b-b863a80bbc95

## Author
frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'

## Date
2021-10-25

## Tags
attack.resource-development, attack.t1587.001

## Description
Detects creation of ".vhd"/".vhdx" files by browser processes.
 Malware can use mountable Virtual Hard Disk ".vhd" files to encapsulate payloads and evade security controls.


## References
https://redcanary.com/blog/intelligence-insights-october-2021/
https://www.kaspersky.com/blog/lazarus-vhd-ransomware/36559/
https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/

## False Positives
Legitimate downloads of ".vhd" files would also trigger this

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\brave.exe" OR SrcProcImagePath endswithCIS "\chrome.exe" OR SrcProcImagePath endswithCIS "\firefox.exe" OR SrcProcImagePath endswithCIS "\iexplore.exe" OR SrcProcImagePath endswithCIS "\maxthon.exe" OR SrcProcImagePath endswithCIS "\MicrosoftEdge.exe" OR SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\msedgewebview2.exe" OR SrcProcImagePath endswithCIS "\opera.exe" OR SrcProcImagePath endswithCIS "\safari.exe" OR SrcProcImagePath endswithCIS "\seamonkey.exe" OR SrcProcImagePath endswithCIS "\vivaldi.exe" OR SrcProcImagePath endswithCIS "\whale.exe") AND TgtFilePath containsCIS ".vhd"))

```