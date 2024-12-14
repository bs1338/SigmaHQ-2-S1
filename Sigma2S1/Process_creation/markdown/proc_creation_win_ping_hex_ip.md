# proc_creation_win_ping_hex_ip

## Title
Ping Hex IP

## ID
1a0d4aba-7668-4365-9ce4-6d79ab088dfd

## Author
Florian Roth (Nextron Systems)

## Date
2018-03-23

## Tags
attack.defense-evasion, attack.t1140, attack.t1027

## Description
Detects a ping command that uses a hex encoded IP address

## References
https://github.com/vysecurity/Aggressor-VYSEC/blob/0d61c80387b9432dab64b8b8a9fb52d20cfef80e/ping.cna
https://twitter.com/vysecurity/status/977198418354491392

## False Positives
Unlikely, because no sane admin pings IP addresses in a hexadecimal form

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "0x" AND TgtProcImagePath endswithCIS "\ping.exe"))

```