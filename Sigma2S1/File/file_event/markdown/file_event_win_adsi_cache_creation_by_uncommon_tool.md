# file_event_win_adsi_cache_creation_by_uncommon_tool

## Title
ADSI-Cache File Creation By Uncommon Tool

## ID
75bf09fa-1dd7-4d18-9af9-dd9e492562eb

## Author
xknow @xknow_infosec, Tim Shelton

## Date
2019-03-24

## Tags
attack.t1001.003, attack.command-and-control

## Description
Detects the creation of an "Active Directory Schema Cache File" (.sch) file by an uncommon tool.

## References
https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
https://github.com/fox-it/LDAPFragger

## False Positives
Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\Local\Microsoft\Windows\SchCache\" AND TgtFilePath endswithCIS ".sch") AND (NOT (((SrcProcImagePath endswithCIS ":\Program Files\Cylance\Desktop\CylanceSvc.exe" OR SrcProcImagePath endswithCIS ":\Windows\CCM\CcmExec.exe" OR SrcProcImagePath endswithCIS ":\windows\system32\dllhost.exe" OR SrcProcImagePath endswithCIS ":\Windows\system32\dsac.exe" OR SrcProcImagePath endswithCIS ":\Windows\system32\efsui.exe" OR SrcProcImagePath endswithCIS ":\windows\system32\mmc.exe" OR SrcProcImagePath endswithCIS ":\windows\system32\svchost.exe" OR SrcProcImagePath endswithCIS ":\Windows\System32\wbem\WmiPrvSE.exe" OR SrcProcImagePath endswithCIS ":\windows\system32\WindowsPowerShell\v1.0\powershell.exe") OR (SrcProcImagePath containsCIS ":\Windows\ccmsetup\autoupgrade\ccmsetup" OR SrcProcImagePath containsCIS ":\Program Files\SentinelOne\Sentinel Agent")) OR ((SrcProcImagePath containsCIS ":\Program Files\" AND SrcProcImagePath containsCIS "\Microsoft Office") AND SrcProcImagePath endswithCIS "\OUTLOOK.EXE"))) AND (NOT (SrcProcImagePath endswithCIS ":\Program Files\Citrix\Receiver StoreFront\Services\DefaultDomainServices\Citrix.DeliveryServices.DomainServices.ServiceHost.exe" OR SrcProcImagePath endswithCIS "\LANDesk\LDCLient\ldapwhoami.exe"))))

```