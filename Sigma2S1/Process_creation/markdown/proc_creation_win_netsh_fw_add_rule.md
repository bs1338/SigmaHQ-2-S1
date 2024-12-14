# proc_creation_win_netsh_fw_add_rule

## Title
New Firewall Rule Added Via Netsh.EXE

## ID
cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c

## Author
Markus Neis, Sander Wiebing

## Date
2019-01-29

## Tags
attack.defense-evasion, attack.t1562.004, attack.s0246

## Description
Detects the addition of a new rule to the Windows firewall via netsh

## References
https://web.archive.org/web/20190508165435/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf

## False Positives
Legitimate administration activity
Software installations

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " firewall " AND TgtProcCmdLine containsCIS " add ") AND TgtProcImagePath endswithCIS "\netsh.exe") AND (NOT (TgtProcCmdLine = "*advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=*:\Program Files (x86)\Dropbox\Client\Dropbox.exe\" enable=yes profile=Any*" OR TgtProcCmdLine = "*advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=*:\Program Files\Dropbox\Client\Dropbox.exe\" enable=yes profile=Any*"))))

```