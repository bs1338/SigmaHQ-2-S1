# proc_creation_win_rundll32_susp_activity

## Title
Potentially Suspicious Rundll32 Activity

## ID
e593cf51-88db-4ee1-b920-37e89012a3c9

## Author
juju4, Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-01-16

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects suspicious execution of rundll32, with specific calls to some DLLs with known LOLBIN functionalities

## References
http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/
https://twitter.com/Hexacorn/status/885258886428725250
https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52
https://twitter.com/nas_bench/status/1433344116071583746
https://twitter.com/eral4m/status/1479106975967240209
https://twitter.com/eral4m/status/1479080793003671557

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "javascript:" AND TgtProcCmdLine containsCIS ".RegisterXLL") OR (TgtProcCmdLine containsCIS "url.dll" AND TgtProcCmdLine containsCIS "OpenURL") OR (TgtProcCmdLine containsCIS "url.dll" AND TgtProcCmdLine containsCIS "OpenURLA") OR (TgtProcCmdLine containsCIS "url.dll" AND TgtProcCmdLine containsCIS "FileProtocolHandler") OR (TgtProcCmdLine containsCIS "zipfldr.dll" AND TgtProcCmdLine containsCIS "RouteTheCall") OR (TgtProcCmdLine containsCIS "shell32.dll" AND TgtProcCmdLine containsCIS "Control_RunDLL") OR (TgtProcCmdLine containsCIS "shell32.dll" AND TgtProcCmdLine containsCIS "ShellExec_RunDLL") OR (TgtProcCmdLine containsCIS "mshtml.dll" AND TgtProcCmdLine containsCIS "PrintHTML") OR (TgtProcCmdLine containsCIS "advpack.dll" AND TgtProcCmdLine containsCIS "LaunchINFSection") OR (TgtProcCmdLine containsCIS "advpack.dll" AND TgtProcCmdLine containsCIS "RegisterOCX") OR (TgtProcCmdLine containsCIS "ieadvpack.dll" AND TgtProcCmdLine containsCIS "LaunchINFSection") OR (TgtProcCmdLine containsCIS "ieadvpack.dll" AND TgtProcCmdLine containsCIS "RegisterOCX") OR (TgtProcCmdLine containsCIS "ieframe.dll" AND TgtProcCmdLine containsCIS "OpenURL") OR (TgtProcCmdLine containsCIS "shdocvw.dll" AND TgtProcCmdLine containsCIS "OpenURL") OR (TgtProcCmdLine containsCIS "syssetup.dll" AND TgtProcCmdLine containsCIS "SetupInfObjectInstallAction") OR (TgtProcCmdLine containsCIS "setupapi.dll" AND TgtProcCmdLine containsCIS "InstallHinfSection") OR (TgtProcCmdLine containsCIS "pcwutl.dll" AND TgtProcCmdLine containsCIS "LaunchApplication") OR (TgtProcCmdLine containsCIS "dfshim.dll" AND TgtProcCmdLine containsCIS "ShOpenVerbApplication") OR (TgtProcCmdLine containsCIS "dfshim.dll" AND TgtProcCmdLine containsCIS "ShOpenVerbShortcut") OR (TgtProcCmdLine containsCIS "scrobj.dll" AND TgtProcCmdLine containsCIS "GenerateTypeLib" AND TgtProcCmdLine containsCIS "http") OR (TgtProcCmdLine containsCIS "shimgvw.dll" AND TgtProcCmdLine containsCIS "ImageView_Fullscreen" AND TgtProcCmdLine containsCIS "http") OR (TgtProcCmdLine containsCIS "comsvcs.dll" AND TgtProcCmdLine containsCIS "MiniDump")) AND (NOT (((TgtProcCmdLine containsCIS "Shell32.dll" AND TgtProcCmdLine containsCIS "Control_RunDLL" AND TgtProcCmdLine containsCIS ".cpl") AND SrcProcCmdLine containsCIS ".cpl" AND SrcProcImagePath = "C:\Windows\System32\control.exe") OR TgtProcCmdLine containsCIS "shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver" OR (TgtProcCmdLine endswithCIS ".cpl\"," AND TgtProcCmdLine startswithCIS "\"C:\Windows\system32\rundll32.exe\" Shell32.dll,Control_RunDLL \"C:\Windows\System32\" AND SrcProcImagePath = "C:\Windows\System32\control.exe")))))

```