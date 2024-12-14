# file_event_win_office_onenote_susp_dropped_files

## Title
Suspicious File Created Via OneNote Application

## ID
fcc6d700-68d9-4241-9a1a-06874d621b06

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-09

## Tags
attack.defense-evasion

## Description
Detects suspicious files created via the OneNote application. This could indicate a potential malicious ".one"/".onepkg" file was executed as seen being used in malware activity in the wild

## References
https://www.bleepingcomputer.com/news/security/hackers-now-use-microsoft-onenote-attachments-to-spread-malware/
https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/
https://twitter.com/MaD_c4t/status/1623414582382567424
https://labs.withsecure.com/publications/detecting-onenote-abuse
https://www.trustedsec.com/blog/new-attacks-old-tricks-how-onenote-malware-is-evolving/
https://app.any.run/tasks/17f2d378-6d11-4d6f-8340-954b04f35e83/

## False Positives
False positives should be very low with the extensions list cited. Especially if you don't heavily utilize OneNote.
Occasional FPs might occur if OneNote is used internally to share different embedded documents

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\onenote.exe" OR SrcProcImagePath endswithCIS "\onenotem.exe" OR SrcProcImagePath endswithCIS "\onenoteim.exe") AND TgtFilePath containsCIS "\AppData\Local\Temp\OneNote\" AND (TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".chm" OR TgtFilePath endswithCIS ".cmd" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".htm" OR TgtFilePath endswithCIS ".html" OR TgtFilePath endswithCIS ".js" OR TgtFilePath endswithCIS ".lnk" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs" OR TgtFilePath endswithCIS ".wsf")))

```