# proc_creation_win_powershell_dsinternals_cmdlets

## Title
DSInternals Suspicious PowerShell Cmdlets

## ID
43d91656-a9b2-4541-b7e2-6a9bd3a13f4e

## Author
Nasreddine Bencherchali (Nextron Systems), Nounou Mbeiri

## Date
2024-06-26

## Tags
attack.execution, attack.t1059.001

## Description
Detects execution and usage of the DSInternals PowerShell module. Which can be used to perform what might be considered as suspicious activity such as dumping DPAPI backup keys or manipulating NTDS.DIT files.
The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory. These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.


## References
https://github.com/MichaelGrafnetter/DSInternals/blob/39ee8a69bbdc1cfd12c9afdd7513b4788c4895d4/Src/DSInternals.PowerShell/DSInternals.psd1

## False Positives
Legitimate usage of DSInternals for administration or audit purpose.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Add-ADDBSidHistory" OR TgtProcCmdLine containsCIS "Add-ADNgcKey" OR TgtProcCmdLine containsCIS "Add-ADReplNgcKey" OR TgtProcCmdLine containsCIS "ConvertFrom-ADManagedPasswordBlob" OR TgtProcCmdLine containsCIS "ConvertFrom-GPPrefPassword" OR TgtProcCmdLine containsCIS "ConvertFrom-ManagedPasswordBlob" OR TgtProcCmdLine containsCIS "ConvertFrom-UnattendXmlPassword" OR TgtProcCmdLine containsCIS "ConvertFrom-UnicodePassword" OR TgtProcCmdLine containsCIS "ConvertTo-AADHash" OR TgtProcCmdLine containsCIS "ConvertTo-GPPrefPassword" OR TgtProcCmdLine containsCIS "ConvertTo-KerberosKey" OR TgtProcCmdLine containsCIS "ConvertTo-LMHash" OR TgtProcCmdLine containsCIS "ConvertTo-MsoPasswordHash" OR TgtProcCmdLine containsCIS "ConvertTo-NTHash" OR TgtProcCmdLine containsCIS "ConvertTo-OrgIdHash" OR TgtProcCmdLine containsCIS "ConvertTo-UnicodePassword" OR TgtProcCmdLine containsCIS "Disable-ADDBAccount" OR TgtProcCmdLine containsCIS "Enable-ADDBAccount" OR TgtProcCmdLine containsCIS "Get-ADDBAccount" OR TgtProcCmdLine containsCIS "Get-ADDBBackupKey" OR TgtProcCmdLine containsCIS "Get-ADDBDomainController" OR TgtProcCmdLine containsCIS "Get-ADDBGroupManagedServiceAccount" OR TgtProcCmdLine containsCIS "Get-ADDBKdsRootKey" OR TgtProcCmdLine containsCIS "Get-ADDBSchemaAttribute" OR TgtProcCmdLine containsCIS "Get-ADDBServiceAccount" OR TgtProcCmdLine containsCIS "Get-ADDefaultPasswordPolicy" OR TgtProcCmdLine containsCIS "Get-ADKeyCredential" OR TgtProcCmdLine containsCIS "Get-ADPasswordPolicy" OR TgtProcCmdLine containsCIS "Get-ADReplAccount" OR TgtProcCmdLine containsCIS "Get-ADReplBackupKey" OR TgtProcCmdLine containsCIS "Get-ADReplicationAccount" OR TgtProcCmdLine containsCIS "Get-ADSIAccount" OR TgtProcCmdLine containsCIS "Get-AzureADUserEx" OR TgtProcCmdLine containsCIS "Get-BootKey" OR TgtProcCmdLine containsCIS "Get-KeyCredential" OR TgtProcCmdLine containsCIS "Get-LsaBackupKey" OR TgtProcCmdLine containsCIS "Get-LsaPolicy" OR TgtProcCmdLine containsCIS "Get-SamPasswordPolicy" OR TgtProcCmdLine containsCIS "Get-SysKey" OR TgtProcCmdLine containsCIS "Get-SystemKey" OR TgtProcCmdLine containsCIS "New-ADDBRestoreFromMediaScript" OR TgtProcCmdLine containsCIS "New-ADKeyCredential" OR TgtProcCmdLine containsCIS "New-ADNgcKey" OR TgtProcCmdLine containsCIS "New-NTHashSet" OR TgtProcCmdLine containsCIS "Remove-ADDBObject" OR TgtProcCmdLine containsCIS "Save-DPAPIBlob" OR TgtProcCmdLine containsCIS "Set-ADAccountPasswordHash" OR TgtProcCmdLine containsCIS "Set-ADDBAccountPassword" OR TgtProcCmdLine containsCIS "Set-ADDBBootKey" OR TgtProcCmdLine containsCIS "Set-ADDBDomainController" OR TgtProcCmdLine containsCIS "Set-ADDBPrimaryGroup" OR TgtProcCmdLine containsCIS "Set-ADDBSysKey" OR TgtProcCmdLine containsCIS "Set-AzureADUserEx" OR TgtProcCmdLine containsCIS "Set-LsaPolicy" OR TgtProcCmdLine containsCIS "Set-SamAccountPasswordHash" OR TgtProcCmdLine containsCIS "Set-WinUserPasswordHash" OR TgtProcCmdLine containsCIS "Test-ADDBPasswordQuality" OR TgtProcCmdLine containsCIS "Test-ADPasswordQuality" OR TgtProcCmdLine containsCIS "Test-ADReplPasswordQuality" OR TgtProcCmdLine containsCIS "Test-PasswordQuality" OR TgtProcCmdLine containsCIS "Unlock-ADDBAccount" OR TgtProcCmdLine containsCIS "Write-ADNgcKey" OR TgtProcCmdLine containsCIS "Write-ADReplNgcKey"))

```