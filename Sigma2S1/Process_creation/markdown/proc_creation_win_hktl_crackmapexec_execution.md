# proc_creation_win_hktl_crackmapexec_execution

## Title
HackTool - CrackMapExec Execution

## ID
42a993dd-bb3e-48c8-b372-4d6684c4106c

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-25

## Tags
attack.execution, attack.persistence, attack.privilege-escalation, attack.credential-access, attack.discovery, attack.t1047, attack.t1053, attack.t1059.003, attack.t1059.001, attack.t1110, attack.t1201

## Description
This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced.

## References
https://mpgn.gitbook.io/crackmapexec/smb-protocol/authentication/checking-credentials-local
https://www.mandiant.com/resources/telegram-malware-iranian-espionage
https://www.infosecmatter.com/crackmapexec-module-library/?cmem=mssql-mimikatz
https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-pe_inject

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\crackmapexec.exe" OR (TgtProcCmdLine containsCIS " --local-auth" AND TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -x ") OR (TgtProcCmdLine containsCIS " --local-auth" AND TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -p " AND TgtProcCmdLine containsCIS " -H 'NTHASH'") OR (TgtProcCmdLine containsCIS " mssql " AND TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -p " AND TgtProcCmdLine containsCIS " -M " AND TgtProcCmdLine containsCIS " -d ") OR (TgtProcCmdLine containsCIS " smb " AND TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -H " AND TgtProcCmdLine containsCIS " -M " AND TgtProcCmdLine containsCIS " -o ") OR (TgtProcCmdLine containsCIS " smb " AND TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -p " AND TgtProcCmdLine containsCIS " --local-auth") OR TgtProcCmdLine containsCIS " -M pe_inject ") OR ((TgtProcCmdLine containsCIS " --local-auth" AND TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -p ") AND (TgtProcCmdLine containsCIS " 10." AND TgtProcCmdLine containsCIS " 192.168." AND TgtProcCmdLine containsCIS "/24 "))))

```