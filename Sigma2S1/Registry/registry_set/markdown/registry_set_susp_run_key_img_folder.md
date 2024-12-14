# registry_set_susp_run_key_img_folder

## Title
New RUN Key Pointing to Suspicious Folder

## ID
02ee49e2-e294-4d0f-9278-f5b3212fc588

## Author
Florian Roth (Nextron Systems), Markus Neis, Sander Wiebing

## Date
2018-08-25

## Tags
attack.persistence, attack.t1547.001

## Description
Detects suspicious new RUN key element pointing to an executable in a suspicious folder

## References
https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html

## False Positives
Software using weird folders for updates

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((((RegistryValue containsCIS ":\$Recycle.bin\" OR RegistryValue containsCIS ":\Temp\" OR RegistryValue containsCIS ":\Users\Default\" OR RegistryValue containsCIS ":\Users\Desktop\" OR RegistryValue containsCIS ":\Users\Public\" OR RegistryValue containsCIS ":\Windows\Temp\" OR RegistryValue containsCIS "\AppData\Local\Temp\" OR RegistryValue containsCIS "%temp%\" OR RegistryValue containsCIS "%tmp%\") OR (RegistryValue startswithCIS "%Public%\" OR RegistryValue startswithCIS "wscript" OR RegistryValue startswithCIS "cscript")) AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\")) AND (NOT ((RegistryValue containsCIS "\AppData\Local\Temp\" OR RegistryValue containsCIS "C:\Windows\Temp\") AND (RegistryValue containsCIS "rundll32.exe " AND RegistryValue containsCIS "C:\WINDOWS\system32\advpack.dll,DelNodeRunDLL32") AND SrcProcImagePath startswithCIS "C:\Windows\SoftwareDistribution\Download\" AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\RunOnce\"))))

```