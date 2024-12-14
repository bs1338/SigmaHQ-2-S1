# file_event_win_iso_file_recent

## Title
ISO or Image Mount Indicator in Recent Files

## ID
4358e5a5-7542-4dcb-b9f3-87667371839b

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-11

## Tags
attack.initial-access, attack.t1566.001

## Description
Detects the creation of recent element file that points to an .ISO, .IMG, .VHD or .VHDX file as often used in phishing attacks.
This can be a false positive on server systems but on workstations users should rarely mount .iso or .img files.


## References
https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
https://blog.emsisoft.com/en/32373/beware-new-wave-of-malware-spreads-via-iso-file-email-attachments/
https://insights.sei.cmu.edu/blog/the-dangers-of-vhd-and-vhdx-files/

## False Positives
Cases in which a user mounts an image file for legitimate reasons

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "\Microsoft\Windows\Recent\" AND (TgtFilePath endswithCIS ".iso.lnk" OR TgtFilePath endswithCIS ".img.lnk" OR TgtFilePath endswithCIS ".vhd.lnk" OR TgtFilePath endswithCIS ".vhdx.lnk")))

```