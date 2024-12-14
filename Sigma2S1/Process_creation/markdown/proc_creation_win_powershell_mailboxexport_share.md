# proc_creation_win_powershell_mailboxexport_share

## Title
Suspicious PowerShell Mailbox Export to Share

## ID
889719ef-dd62-43df-86c3-768fb08dc7c0

## Author
Florian Roth (Nextron Systems)

## Date
2021-08-07

## Tags
attack.exfiltration

## Description
Detects usage of the powerShell New-MailboxExportRequest Cmdlet to exports a mailbox to a remote or local share, as used in ProxyShell exploitations

## References
https://youtu.be/5mqid-7zp8k?t=2481
https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html
https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1
https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "New-MailboxExportRequest" AND TgtProcCmdLine containsCIS " -Mailbox " AND TgtProcCmdLine containsCIS " -FilePath \\"))

```