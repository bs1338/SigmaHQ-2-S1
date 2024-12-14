# file_event_win_hktl_krbrelay_remote_ioc

## Title
HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators

## ID
3ab79e90-9fab-4cdf-a7b2-6522bc742adb

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-06-27

## Tags
attack.command-and-control, attack.t1219

## Description
Detects the creation of file with specific names used by RemoteKrbRelay SMB Relay attack module.

## References
https://github.com/CICADA8-Research/RemoteKrbRelay/blob/19ec76ba7aa50c2722b23359bc4541c0a9b2611c/Exploit/RemoteKrbRelay/Relay/Attacks/RemoteRegistry.cs#L31-L40

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ":\windows\temp\sam.tmp" OR TgtFilePath endswithCIS ":\windows\temp\sec.tmp" OR TgtFilePath endswithCIS ":\windows\temp\sys.tmp"))

```