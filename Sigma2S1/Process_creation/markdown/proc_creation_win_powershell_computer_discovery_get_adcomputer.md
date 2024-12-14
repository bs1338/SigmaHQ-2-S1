# proc_creation_win_powershell_computer_discovery_get_adcomputer

## Title
Computer Discovery And Export Via Get-ADComputer Cmdlet

## ID
435e10e4-992a-4281-96f3-38b11106adde

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-11-10

## Tags
attack.discovery, attack.t1033

## Description
Detects usage of the Get-ADComputer cmdlet to collect computer information and output it to a file

## References
http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
https://www.cisa.gov/uscert/sites/default/files/publications/aa22-320a_joint_csa_iranian_government-sponsored_apt_actors_compromise_federal%20network_deploy_crypto%20miner_credential_harvester.pdf

## False Positives
Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " > " OR TgtProcCmdLine containsCIS " | Select " OR TgtProcCmdLine containsCIS "Out-File" OR TgtProcCmdLine containsCIS "Set-Content" OR TgtProcCmdLine containsCIS "Add-Content") AND (TgtProcCmdLine containsCIS "Get-ADComputer " AND TgtProcCmdLine containsCIS " -Filter \*")) AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```