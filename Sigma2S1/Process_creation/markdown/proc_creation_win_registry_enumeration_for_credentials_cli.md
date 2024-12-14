# proc_creation_win_registry_enumeration_for_credentials_cli

## Title
Enumeration for 3rd Party Creds From CLI

## ID
87a476dc-0079-4583-a985-dee7a20a03de

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-20

## Tags
attack.credential-access, attack.t1552.002

## Description
Detects processes that query known 3rd party registry keys that holds credentials via commandline

## References
https://isc.sans.edu/diary/More+Data+Exfiltration/25698
https://github.com/synacktiv/Radmin3-Password-Cracker/blob/acfc87393e4b7c06353973a14a6c7126a51f36ac/regkey.txt
https://github.com/HyperSine/how-does-MobaXterm-encrypt-password
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#inside-the-registry

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\Software\SimonTatham\PuTTY\Sessions" OR TgtProcCmdLine containsCIS "\Software\SimonTatham\PuTTY\SshHostKeys\" OR TgtProcCmdLine containsCIS "\Software\Mobatek\MobaXterm\" OR TgtProcCmdLine containsCIS "\Software\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin" OR TgtProcCmdLine containsCIS "\Software\Aerofox\FoxmailPreview" OR TgtProcCmdLine containsCIS "\Software\Aerofox\Foxmail\V3.1" OR TgtProcCmdLine containsCIS "\Software\IncrediMail\Identities" OR TgtProcCmdLine containsCIS "\Software\Qualcomm\Eudora\CommandLine" OR TgtProcCmdLine containsCIS "\Software\RimArts\B2\Settings" OR TgtProcCmdLine containsCIS "\Software\OpenVPN-GUI\configs" OR TgtProcCmdLine containsCIS "\Software\Martin Prikryl\WinSCP 2\Sessions" OR TgtProcCmdLine containsCIS "\Software\FTPWare\COREFTP\Sites" OR TgtProcCmdLine containsCIS "\Software\DownloadManager\Passwords" OR TgtProcCmdLine containsCIS "\Software\OpenSSH\Agent\Keys" OR TgtProcCmdLine containsCIS "\Software\TightVNC\Server" OR TgtProcCmdLine containsCIS "\Software\ORL\WinVNC3\Password" OR TgtProcCmdLine containsCIS "\Software\RealVNC\WinVNC4"))

```