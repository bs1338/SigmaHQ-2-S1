# file_event_win_notepad_plus_plus_persistence

## Title
Potential Persistence Via Notepad++ Plugins

## ID
54127bd4-f541-4ac3-afdb-ea073f63f692

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-10

## Tags
attack.persistence

## Description
Detects creation of new ".dll" files inside the plugins directory of a notepad++ installation by a process other than "gup.exe". Which could indicates possible persistence

## References
https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/

## False Positives
Possible FPs during first installation of Notepad++
Legitimate use of custom plugins by users in order to enhance notepad++ functionalities

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\Notepad++\plugins\" AND TgtFilePath endswithCIS ".dll") AND (NOT (SrcProcImagePath endswithCIS "\Notepad++\updater\gup.exe" OR (SrcProcImagePath containsCIS "\AppData\Local\Temp\" AND (SrcProcImagePath endswithCIS "\target.exe" OR SrcProcImagePath endswithCIS "Installer.x64.exe") AND SrcProcImagePath startswithCIS "C:\Users\")))))

```