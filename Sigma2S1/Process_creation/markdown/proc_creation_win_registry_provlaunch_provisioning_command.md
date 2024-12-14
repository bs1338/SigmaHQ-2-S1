# proc_creation_win_registry_provlaunch_provisioning_command

## Title
Potential Provisioning Registry Key Abuse For Binary Proxy Execution

## ID
2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25

## Author
Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel

## Date
2023-08-08

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects potential abuse of the provisioning registry key for indirect command execution through "Provlaunch.exe".

## References
https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
https://twitter.com/0gtweet/status/1674399582162153472

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "SOFTWARE\Microsoft\Provisioning\Commands\")

```