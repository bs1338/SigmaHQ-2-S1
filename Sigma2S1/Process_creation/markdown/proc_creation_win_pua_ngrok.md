# proc_creation_win_pua_ngrok

## Title
PUA - Ngrok Execution

## ID
ee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31

## Author
Florian Roth (Nextron Systems)

## Date
2021-05-14

## Tags
attack.command-and-control, attack.t1572

## Description
Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available.
 Involved domains are bin.equinox.io for download and *.ngrok.io for connections.


## References
https://ngrok.com/docs
https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html
https://stackoverflow.com/questions/42442320/ssh-tunnel-to-ngrok-and-initiate-rdp
https://www.virustotal.com/gui/file/58d21840d915aaf4040ceb89522396124c82f325282f805d1085527e1e2ccfa1/detection
https://cybleinc.com/2021/02/15/ngrok-platform-abused-by-hackers-to-deliver-a-new-wave-of-phishing-attacks/
https://twitter.com/xorJosh/status/1598646907802451969
https://www.softwaretestinghelp.com/how-to-use-ngrok/

## False Positives
Another tool that uses the command line switches of Ngrok
Ngrok http 3978 (https://learn.microsoft.com/en-us/azure/bot-service/bot-service-debug-channel-ngrok?view=azure-bot-service-4.0)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " tcp 139" OR TgtProcCmdLine containsCIS " tcp 445" OR TgtProcCmdLine containsCIS " tcp 3389" OR TgtProcCmdLine containsCIS " tcp 5985" OR TgtProcCmdLine containsCIS " tcp 5986") OR (TgtProcCmdLine containsCIS " start " AND TgtProcCmdLine containsCIS "--all" AND TgtProcCmdLine containsCIS "--config" AND TgtProcCmdLine containsCIS ".yml") OR ((TgtProcCmdLine containsCIS " tcp " OR TgtProcCmdLine containsCIS " http " OR TgtProcCmdLine containsCIS " authtoken ") AND TgtProcImagePath endswithCIS "ngrok.exe") OR (TgtProcCmdLine containsCIS ".exe authtoken " OR TgtProcCmdLine containsCIS ".exe start --all")))

```