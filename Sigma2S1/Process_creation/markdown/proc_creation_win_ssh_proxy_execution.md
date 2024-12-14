# proc_creation_win_ssh_proxy_execution

## Title
Program Executed Using Proxy/Local Command Via SSH.EXE

## ID
7d6d30b8-5b91-4b90-a891-46cccaf29598

## Author
frack113, Nasreddine Bencherchali

## Date
2022-12-29

## Tags
attack.defense-evasion, attack.t1218

## Description
Detect usage of the "ssh.exe" binary as a proxy to launch other programs.

## References
https://lolbas-project.github.io/lolbas/Binaries/Ssh/
https://github.com/LOLBAS-Project/LOLBAS/pull/211/files
https://gtfobins.github.io/gtfobins/ssh/
https://man.openbsd.org/ssh_config#ProxyCommand
https://man.openbsd.org/ssh_config#LocalCommand

## False Positives
Legitimate usage for administration purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath = "C:\Windows\System32\OpenSSH\sshd.exe" OR ((TgtProcCmdLine containsCIS "ProxyCommand=" OR (TgtProcCmdLine containsCIS "PermitLocalCommand" AND TgtProcCmdLine containsCIS "LocalCommand")) AND TgtProcImagePath endswithCIS "\ssh.exe")))

```