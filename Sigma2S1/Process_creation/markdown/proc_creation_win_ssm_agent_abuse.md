# proc_creation_win_ssm_agent_abuse

## Title
Potential Amazon SSM Agent Hijacking

## ID
d20ee2f4-822c-4827-9e15-41500b1fff10

## Author
Muhammad Faisal

## Date
2023-08-02

## Tags
attack.command-and-control, attack.persistence, attack.t1219

## Description
Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.

## References
https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/

## False Positives
Legitimate activity of system administrators

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-register " AND TgtProcCmdLine containsCIS "-code " AND TgtProcCmdLine containsCIS "-id " AND TgtProcCmdLine containsCIS "-region ") AND TgtProcImagePath endswithCIS "\amazon-ssm-agent.exe"))

```