# registry_event_stickykey_like_backdoor

## Title
Sticky Key Like Backdoor Usage - Registry

## ID
baca5663-583c-45f9-b5dc-ea96a22ce542

## Author
Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community

## Date
2018-03-15

## Tags
attack.privilege-escalation, attack.persistence, attack.t1546.008, car.2014-11-003, car.2014-11-008

## Description
Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen

## References
https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger" OR RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger" OR RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Debugger" OR RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe\Debugger" OR RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe\Debugger" OR RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe\Debugger" OR RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe\Debugger" OR RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HelpPane.exe\Debugger"))

```