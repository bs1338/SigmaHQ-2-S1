# file_event_win_iso_file_mount

## Title
ISO File Created Within Temp Folders

## ID
2f9356ae-bf43-41b8-b858-4496d83b2acb

## Author
@sam0x90

## Date
2022-07-30

## Tags
attack.initial-access, attack.t1566.001

## Description
Detects the creation of a ISO file in the Outlook temp folder or in the Appdata temp folder. Typical of Qakbot TTP from end-July 2022.

## References
https://twitter.com/Sam0x90/status/1552011547974696960
https://securityaffairs.co/wordpress/133680/malware/dll-sideloading-spread-qakbot.html
https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1553.005/T1553.005.md#atomic-test-1---mount-iso-image

## False Positives
Potential FP by sysadmin opening a zip file containing a legitimate ISO file

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((TgtFilePath containsCIS "\AppData\Local\Temp\" AND TgtFilePath containsCIS ".zip\") AND TgtFilePath endswithCIS ".iso") OR (TgtFilePath containsCIS "\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\" AND TgtFilePath endswithCIS ".iso")))

```