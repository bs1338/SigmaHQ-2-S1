# proc_creation_win_hktl_sharpview

## Title
HackTool - SharpView Execution

## ID
b2317cfa-4a47-4ead-b3ff-297438c0bc2d

## Author
frack113

## Date
2021-12-10

## Tags
attack.discovery, attack.t1049, attack.t1069.002, attack.t1482, attack.t1135, attack.t1033

## Description
Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems

## References
https://github.com/tevora-threat/SharpView/
https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-4---system-discovery-using-sharpview

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SharpView.exe" OR (TgtProcCmdLine containsCIS "Add-RemoteConnection" OR TgtProcCmdLine containsCIS "Convert-ADName" OR TgtProcCmdLine containsCIS "ConvertFrom-SID" OR TgtProcCmdLine containsCIS "ConvertFrom-UACValue" OR TgtProcCmdLine containsCIS "Convert-SidToName" OR TgtProcCmdLine containsCIS "Export-PowerViewCSV" OR TgtProcCmdLine containsCIS "Find-DomainObjectPropertyOutlier" OR TgtProcCmdLine containsCIS "Find-DomainProcess" OR TgtProcCmdLine containsCIS "Find-DomainShare" OR TgtProcCmdLine containsCIS "Find-DomainUserEvent" OR TgtProcCmdLine containsCIS "Find-DomainUserLocation" OR TgtProcCmdLine containsCIS "Find-ForeignGroup" OR TgtProcCmdLine containsCIS "Find-ForeignUser" OR TgtProcCmdLine containsCIS "Find-GPOComputerAdmin" OR TgtProcCmdLine containsCIS "Find-GPOLocation" OR TgtProcCmdLine containsCIS "Find-Interesting" OR TgtProcCmdLine containsCIS "Find-LocalAdminAccess" OR TgtProcCmdLine containsCIS "Find-ManagedSecurityGroups" OR TgtProcCmdLine containsCIS "Get-CachedRDPConnection" OR TgtProcCmdLine containsCIS "Get-DFSshare" OR TgtProcCmdLine containsCIS "Get-DomainComputer" OR TgtProcCmdLine containsCIS "Get-DomainController" OR TgtProcCmdLine containsCIS "Get-DomainDFSShare" OR TgtProcCmdLine containsCIS "Get-DomainDNSRecord" OR TgtProcCmdLine containsCIS "Get-DomainFileServer" OR TgtProcCmdLine containsCIS "Get-DomainForeign" OR TgtProcCmdLine containsCIS "Get-DomainGPO" OR TgtProcCmdLine containsCIS "Get-DomainGroup" OR TgtProcCmdLine containsCIS "Get-DomainGUIDMap" OR TgtProcCmdLine containsCIS "Get-DomainManagedSecurityGroup" OR TgtProcCmdLine containsCIS "Get-DomainObject" OR TgtProcCmdLine containsCIS "Get-DomainOU" OR TgtProcCmdLine containsCIS "Get-DomainPolicy" OR TgtProcCmdLine containsCIS "Get-DomainSID" OR TgtProcCmdLine containsCIS "Get-DomainSite" OR TgtProcCmdLine containsCIS "Get-DomainSPNTicket" OR TgtProcCmdLine containsCIS "Get-DomainSubnet" OR TgtProcCmdLine containsCIS "Get-DomainTrust" OR TgtProcCmdLine containsCIS "Get-DomainUserEvent" OR TgtProcCmdLine containsCIS "Get-ForestDomain" OR TgtProcCmdLine containsCIS "Get-ForestGlobalCatalog" OR TgtProcCmdLine containsCIS "Get-ForestTrust" OR TgtProcCmdLine containsCIS "Get-GptTmpl" OR TgtProcCmdLine containsCIS "Get-GroupsXML" OR TgtProcCmdLine containsCIS "Get-LastLoggedOn" OR TgtProcCmdLine containsCIS "Get-LoggedOnLocal" OR TgtProcCmdLine containsCIS "Get-NetComputer" OR TgtProcCmdLine containsCIS "Get-NetDomain" OR TgtProcCmdLine containsCIS "Get-NetFileServer" OR TgtProcCmdLine containsCIS "Get-NetForest" OR TgtProcCmdLine containsCIS "Get-NetGPO" OR TgtProcCmdLine containsCIS "Get-NetGroupMember" OR TgtProcCmdLine containsCIS "Get-NetLocalGroup" OR TgtProcCmdLine containsCIS "Get-NetLoggedon" OR TgtProcCmdLine containsCIS "Get-NetOU" OR TgtProcCmdLine containsCIS "Get-NetProcess" OR TgtProcCmdLine containsCIS "Get-NetRDPSession" OR TgtProcCmdLine containsCIS "Get-NetSession" OR TgtProcCmdLine containsCIS "Get-NetShare" OR TgtProcCmdLine containsCIS "Get-NetSite" OR TgtProcCmdLine containsCIS "Get-NetSubnet" OR TgtProcCmdLine containsCIS "Get-NetUser" OR TgtProcCmdLine containsCIS "Get-PathAcl" OR TgtProcCmdLine containsCIS "Get-PrincipalContext" OR TgtProcCmdLine containsCIS "Get-RegistryMountedDrive" OR TgtProcCmdLine containsCIS "Get-RegLoggedOn" OR TgtProcCmdLine containsCIS "Get-WMIRegCachedRDPConnection" OR TgtProcCmdLine containsCIS "Get-WMIRegLastLoggedOn" OR TgtProcCmdLine containsCIS "Get-WMIRegMountedDrive" OR TgtProcCmdLine containsCIS "Get-WMIRegProxy" OR TgtProcCmdLine containsCIS "Invoke-ACLScanner" OR TgtProcCmdLine containsCIS "Invoke-CheckLocalAdminAccess" OR TgtProcCmdLine containsCIS "Invoke-Kerberoast" OR TgtProcCmdLine containsCIS "Invoke-MapDomainTrust" OR TgtProcCmdLine containsCIS "Invoke-RevertToSelf" OR TgtProcCmdLine containsCIS "Invoke-Sharefinder" OR TgtProcCmdLine containsCIS "Invoke-UserImpersonation" OR TgtProcCmdLine containsCIS "Remove-DomainObjectAcl" OR TgtProcCmdLine containsCIS "Remove-RemoteConnection" OR TgtProcCmdLine containsCIS "Request-SPNTicket" OR TgtProcCmdLine containsCIS "Set-DomainObject" OR TgtProcCmdLine containsCIS "Test-AdminAccess")))

```