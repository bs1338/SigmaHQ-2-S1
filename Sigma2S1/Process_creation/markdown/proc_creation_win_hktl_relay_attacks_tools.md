# proc_creation_win_hktl_relay_attacks_tools

## Title
Potential SMB Relay Attack Tool Execution

## ID
5589ab4f-a767-433c-961d-c91f3f704db1

## Author
Florian Roth (Nextron Systems)

## Date
2021-07-24

## Tags
attack.execution, attack.t1557.001

## Description
Detects different hacktools used for relay attacks on Windows for privilege escalation

## References
https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
https://pentestlab.blog/2017/04/13/hot-potato/
https://github.com/ohpe/juicy-potato
https://hunter2.gitbook.io/darthsidious/other/war-stories/domain-admin-in-30-minutes
https://hunter2.gitbook.io/darthsidious/execution/responder-with-ntlm-relay-and-empire
https://www.localpotato.com/

## False Positives
Legitimate files with these rare hacktool names

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS ".exe -c \"{" AND TgtProcCmdLine endswithCIS "}\" -z") OR (TgtProcImagePath containsCIS "PetitPotam" OR TgtProcImagePath containsCIS "RottenPotato" OR TgtProcImagePath containsCIS "HotPotato" OR TgtProcImagePath containsCIS "JuicyPotato" OR TgtProcImagePath containsCIS "\just_dce_" OR TgtProcImagePath containsCIS "Juicy Potato" OR TgtProcImagePath containsCIS "\temp\rot.exe" OR TgtProcImagePath containsCIS "\Potato.exe" OR TgtProcImagePath containsCIS "\SpoolSample.exe" OR TgtProcImagePath containsCIS "\Responder.exe" OR TgtProcImagePath containsCIS "\smbrelayx" OR TgtProcImagePath containsCIS "\ntlmrelayx" OR TgtProcImagePath containsCIS "\LocalPotato") OR (TgtProcCmdLine containsCIS "Invoke-Tater" OR TgtProcCmdLine containsCIS " smbrelay" OR TgtProcCmdLine containsCIS " ntlmrelay" OR TgtProcCmdLine containsCIS "cme smb " OR TgtProcCmdLine containsCIS " /ntlm:NTLMhash " OR TgtProcCmdLine containsCIS "Invoke-PetitPotam" OR TgtProcCmdLine = "*.exe -t * -p *")) AND (NOT (TgtProcImagePath containsCIS "HotPotatoes6" OR TgtProcImagePath containsCIS "HotPotatoes7" OR TgtProcImagePath containsCIS "HotPotatoes "))))

```