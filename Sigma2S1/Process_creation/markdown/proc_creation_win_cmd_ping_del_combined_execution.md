# proc_creation_win_cmd_ping_del_combined_execution

## Title
Suspicious Ping/Del Command Combination

## ID
54786ddc-5b8a-11ed-9b6a-0242ac120002

## Author
Ilya Krestinichev

## Date
2022-11-03

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects a method often used by ransomware. Which combines the "ping" to wait a couple of seconds and then "del" to delete the file in question. Its used to hide the file responsible for the initial infection for example

## References
https://blog.sygnia.co/kaseya-ransomware-supply-chain-attack
https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf
https://www.acronis.com/en-us/blog/posts/lockbit-ransomware/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/blackbyte-exbyte-ransomware

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ping" AND TgtProcCmdLine containsCIS "del ") AND (TgtProcCmdLine containsCIS " -n " OR TgtProcCmdLine containsCIS " /n " OR TgtProcCmdLine containsCIS " â€“n " OR TgtProcCmdLine containsCIS " â€”n " OR TgtProcCmdLine containsCIS " â€•n ") AND (TgtProcCmdLine containsCIS " -f " OR TgtProcCmdLine containsCIS " /f " OR TgtProcCmdLine containsCIS " â€“f " OR TgtProcCmdLine containsCIS " â€”f " OR TgtProcCmdLine containsCIS " â€•f " OR TgtProcCmdLine containsCIS " -q " OR TgtProcCmdLine containsCIS " /q " OR TgtProcCmdLine containsCIS " â€“q " OR TgtProcCmdLine containsCIS " â€”q " OR TgtProcCmdLine containsCIS " â€•q ") AND TgtProcCmdLine containsCIS "Nul"))

```