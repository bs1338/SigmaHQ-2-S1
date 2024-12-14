# registry_set_telemetry_persistence

## Title
Potential Registry Persistence Attempt Via Windows Telemetry

## ID
73a883d0-0348-4be4-a8d8-51031c2564f8

## Author
Lednyov Alexey, oscd.community, Sreeman

## Date
2020-10-16

## Tags
attack.persistence, attack.t1053.005

## Description
Detects potential persistence behavior using the windows telemetry registry key.
Windows telemetry makes use of the binary CompatTelRunner.exe to run a variety of commands and perform the actual telemetry collections.
This binary was created to be easily extensible, and to that end, it relies on the registry to instruct on which commands to run.
The problem is, it will run any arbitrary command without restriction of location or type.


## References
https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue containsCIS ".bat" OR RegistryValue containsCIS ".bin" OR RegistryValue containsCIS ".cmd" OR RegistryValue containsCIS ".dat" OR RegistryValue containsCIS ".dll" OR RegistryValue containsCIS ".exe" OR RegistryValue containsCIS ".hta" OR RegistryValue containsCIS ".jar" OR RegistryValue containsCIS ".js" OR RegistryValue containsCIS ".msi" OR RegistryValue containsCIS ".ps" OR RegistryValue containsCIS ".sh" OR RegistryValue containsCIS ".vb") AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\" AND RegistryKeyPath endswithCIS "\Command") AND (NOT (RegistryValue containsCIS "\system32\CompatTelRunner.exe" OR RegistryValue containsCIS "\system32\DeviceCensus.exe"))))

```