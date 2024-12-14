# proc_creation_win_cmd_unusual_parent

## Title
Unusual Parent Process For Cmd.EXE

## ID
4b991083-3d0e-44ce-8fc4-b254025d8d4b

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-21

## Tags
attack.execution, attack.t1059

## Description
Detects suspicious parent process for cmd.exe

## References
https://www.elastic.co/guide/en/security/current/unusual-parent-process-for-cmd.exe.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\cmd.exe" AND (SrcProcImagePath endswithCIS "\csrss.exe" OR SrcProcImagePath endswithCIS "\ctfmon.exe" OR SrcProcImagePath endswithCIS "\dllhost.exe" OR SrcProcImagePath endswithCIS "\epad.exe" OR SrcProcImagePath endswithCIS "\FlashPlayerUpdateService.exe" OR SrcProcImagePath endswithCIS "\GoogleUpdate.exe" OR SrcProcImagePath endswithCIS "\jucheck.exe" OR SrcProcImagePath endswithCIS "\jusched.exe" OR SrcProcImagePath endswithCIS "\LogonUI.exe" OR SrcProcImagePath endswithCIS "\lsass.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\SearchIndexer.exe" OR SrcProcImagePath endswithCIS "\SearchProtocolHost.exe" OR SrcProcImagePath endswithCIS "\SIHClient.exe" OR SrcProcImagePath endswithCIS "\sihost.exe" OR SrcProcImagePath endswithCIS "\slui.exe" OR SrcProcImagePath endswithCIS "\spoolsv.exe" OR SrcProcImagePath endswithCIS "\sppsvc.exe" OR SrcProcImagePath endswithCIS "\taskhostw.exe" OR SrcProcImagePath endswithCIS "\unsecapp.exe" OR SrcProcImagePath endswithCIS "\WerFault.exe" OR SrcProcImagePath endswithCIS "\wermgr.exe" OR SrcProcImagePath endswithCIS "\wlanext.exe" OR SrcProcImagePath endswithCIS "\WUDFHost.exe")))

```