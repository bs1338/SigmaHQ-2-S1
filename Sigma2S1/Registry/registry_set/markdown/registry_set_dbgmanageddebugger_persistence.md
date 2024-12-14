# registry_set_dbgmanageddebugger_persistence

## Title
Potential Registry Persistence Attempt Via DbgManagedDebugger

## ID
9827ae57-3802-418f-994b-d5ecf5cd974b

## Author
frack113

## Date
2022-08-07

## Tags
attack.persistence, attack.t1574

## Description
Detects the addition of the "Debugger" value to the "DbgManagedDebugger" key in order to achieve persistence. Which will get invoked when an application crashes

## References
https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/
https://github.com/last-byte/PersistenceSniper

## False Positives
Legitimate use of the key to setup a debugger. Which is often the case on developers machines

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\Microsoft\.NETFramework\DbgManagedDebugger" AND (NOT RegistryValue = "\"C:\Windows\system32\vsjitdebugger.exe\" PID %d APPDOM %d EXTEXT \"%s\" EVTHDL %d")))

```