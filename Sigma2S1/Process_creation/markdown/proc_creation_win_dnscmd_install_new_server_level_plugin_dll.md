# proc_creation_win_dnscmd_install_new_server_level_plugin_dll

## Title
New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE

## ID
f63b56ee-3f79-4b8a-97fb-5c48007e8573

## Author
Florian Roth (Nextron Systems)

## Date
2017-05-08

## Tags
attack.defense-evasion, attack.t1574.002, attack.t1112

## Description
Detects the installation of a DNS plugin DLL via ServerLevelPluginDll parameter in registry, which can be used to execute code in context of the DNS server (restart required)

## References
https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/config" AND TgtProcCmdLine containsCIS "/serverlevelplugindll") AND TgtProcImagePath endswithCIS "\dnscmd.exe"))

```