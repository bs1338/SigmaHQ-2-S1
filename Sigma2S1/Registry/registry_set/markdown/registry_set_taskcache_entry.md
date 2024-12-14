# registry_set_taskcache_entry

## Title
Scheduled TaskCache Change by Uncommon Program

## ID
4720b7df-40c3-48fd-bbdf-fd4b3c464f0d

## Author
Syed Hasan (@syedhasan009)

## Date
2021-06-18

## Tags
attack.persistence, attack.t1053, attack.t1053.005

## Description
Monitor the creation of a new key under 'TaskCache' when a new scheduled task is registered by a process that is not svchost.exe, which is suspicious

## References
https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
https://labs.f-secure.com/blog/scheduled-task-tampering/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\" AND (NOT ((RegistryKeyPath containsCIS "Microsoft\Windows\UpdateOrchestrator" OR RegistryKeyPath containsCIS "Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask\Index" OR RegistryKeyPath containsCIS "Microsoft\Windows\Flighting\OneSettings\RefreshCache\Index") OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe","C:\Program Files\Dropbox\Update\DropboxUpdate.exe")) OR (SrcProcImagePath = "C:\Windows\explorer.exe" AND RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\PLA\Server Manager Performance Monitor\") OR SrcProcImagePath = "C:\Windows\System32\msiexec.exe" OR (SrcProcImagePath endswithCIS "\ngen.exe" AND SrcProcImagePath startswithCIS "C:\Windows\Microsoft.NET\Framework" AND (RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B66B135D-DA06-4FC4-95F8-7458E1D10129}" OR RegistryKeyPath containsCIS "\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\.NET Framework\.NET Framework NGEN")) OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Microsoft Office\root\Integration\Integrator.exe","C:\Program Files (x86)\Microsoft Office\root\Integration\Integrator.exe")) OR SrcProcImagePath = "C:\WINDOWS\system32\svchost.exe" OR SrcProcImagePath = "System" OR (SrcProcImagePath endswithCIS "\TiWorker.exe" AND SrcProcImagePath startswithCIS "C:\Windows\")))))

```