# registry_set_aedebug_persistence

## Title
Add Debugger Entry To AeDebug For Persistence

## ID
092af964-4233-4373-b4ba-d86ea2890288

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker adds a new "Debugger" value to the "AeDebug" key in order to achieve persistence which will get invoked when an application crashes

## References
https://persistence-info.github.io/Data/aedebug.html
https://learn.microsoft.com/en-us/windows/win32/debug/configuring-automatic-debugging

## False Positives
Legitimate use of the key to setup a debugger. Which is often the case on developers machines

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue endswithCIS ".dll" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\Debugger") AND (NOT RegistryValue = "\"C:\WINDOWS\system32\vsjitdebugger.exe\" -p %ld -e %ld -j 0x%p")))

```