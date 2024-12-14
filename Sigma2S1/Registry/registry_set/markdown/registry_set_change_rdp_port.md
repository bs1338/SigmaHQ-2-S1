# registry_set_change_rdp_port

## Title
Default RDP Port Changed to Non Standard Port

## ID
509e84b9-a71a-40e0-834f-05470369bd1e

## Author
frack113

## Date
2022-01-01

## Tags
attack.persistence, attack.t1547.010

## Description
Detects changes to the default RDP port.
Remote desktop is a common feature in operating systems. It allows a user to log into a remote system using an interactive session with a graphical user interface.
Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.001/T1021.001.md#atomic-test-1---rdp-to-domaincontroller

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber" AND (NOT RegistryValue = "DWORD (0x00000d3d)")))

```