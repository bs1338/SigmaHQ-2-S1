# proc_creation_win_net_groups_and_accounts_recon

## Title
Suspicious Group And Account Reconnaissance Activity Using Net.EXE

## ID
d95de845-b83c-4a9a-8a6a-4fc802ebf6c0

## Author
Florian Roth (Nextron Systems), omkar72, @svch0st, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-01-16

## Tags
attack.discovery, attack.t1087.001, attack.t1087.002

## Description
Detects suspicious reconnaissance command line activity on Windows systems using Net.EXE
Check if the user that executed the commands is suspicious (e.g. service accounts, LOCAL_SYSTEM)


## References
https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/
https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/

## False Positives
Inventory tool runs
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe") AND ((((TgtProcCmdLine containsCIS "domain admins" OR TgtProcCmdLine containsCIS " administrator" OR TgtProcCmdLine containsCIS " administrateur" OR TgtProcCmdLine containsCIS "enterprise admins" OR TgtProcCmdLine containsCIS "Exchange Trusted Subsystem" OR TgtProcCmdLine containsCIS "Remote Desktop Users" OR TgtProcCmdLine containsCIS "Utilisateurs du Bureau Ã  distance" OR TgtProcCmdLine containsCIS "Usuarios de escritorio remoto" OR TgtProcCmdLine containsCIS " /do") AND (TgtProcCmdLine containsCIS " group " OR TgtProcCmdLine containsCIS " localgroup ")) AND (NOT TgtProcCmdLine containsCIS " /add")) OR (TgtProcCmdLine containsCIS " /do" AND TgtProcCmdLine containsCIS " accounts "))))

```