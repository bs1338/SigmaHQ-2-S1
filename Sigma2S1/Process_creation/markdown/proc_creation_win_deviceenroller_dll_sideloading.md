# proc_creation_win_deviceenroller_dll_sideloading

## Title
Potential DLL Sideloading Via DeviceEnroller.EXE

## ID
e173ad47-4388-4012-ae62-bd13f71c18a8

## Author
@gott_cyber

## Date
2022-08-29

## Tags
attack.defense-evasion, attack.t1574.002

## Description
Detects the use of the PhoneDeepLink parameter to potentially sideload a DLL file that does not exist. This non-existent DLL file is named "ShellChromeAPI.dll".
Adversaries can drop their own renamed DLL and execute it via DeviceEnroller.exe using this parameter


## References
https://mobile.twitter.com/0gtweet/status/1564131230941122561
https://strontic.github.io/xcyclopedia/library/DeviceEnroller.exe-24BEF0D6B0ECED36BB41831759FDE18D.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/PhoneDeepLink" AND TgtProcImagePath endswithCIS "\deviceenroller.exe"))

```