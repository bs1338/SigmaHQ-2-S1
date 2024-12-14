# file_event_win_iphlpapi_dll_sideloading

## Title
Malicious DLL File Dropped in the Teams or OneDrive Folder

## ID
1908fcc1-1b92-4272-8214-0fbaf2fa5163

## Author
frack113

## Date
2022-08-12

## Tags
attack.persistence, attack.privilege-escalation, attack.defense-evasion, attack.t1574.002

## Description
Detects creation of a malicious DLL file in the location where the OneDrive or Team applications
Upon execution of the Teams or OneDrive application, the dropped malicious DLL file ("iphlpapi.dll") is sideloaded


## References
https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "iphlpapi.dll" AND TgtFilePath containsCIS "\AppData\Local\Microsoft"))

```