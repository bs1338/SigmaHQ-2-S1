# proc_creation_win_userinit_uncommon_child_processes

## Title
Uncommon Userinit Child Process

## ID
0a98a10c-685d-4ab0-bddc-b6bdd1d48458

## Author
Tom Ueltschi (@c_APT_ure), Tim Shelton

## Date
2019-01-12

## Tags
attack.t1037.001, attack.persistence

## Description
Detects uncommon "userinit.exe" child processes, which could be a sign of uncommon shells or login scripts used for persistence.

## References
https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html
https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-sconfig#powershell-is-the-default-shell-on-server-core

## False Positives
Legitimate logon scripts or custom shells may trigger false positives. Apply additional filters accordingly.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\userinit.exe" AND (NOT TgtProcImagePath endswithCIS ":\WINDOWS\explorer.exe") AND (NOT ((TgtProcImagePath endswithCIS ":\Program Files (x86)\Citrix\HDX\bin\cmstart.exe" OR TgtProcImagePath endswithCIS ":\Program Files (x86)\Citrix\HDX\bin\icast.exe" OR TgtProcImagePath endswithCIS ":\Program Files (x86)\Citrix\System32\icast.exe" OR TgtProcImagePath endswithCIS ":\Program Files\Citrix\HDX\bin\cmstart.exe" OR TgtProcImagePath endswithCIS ":\Program Files\Citrix\HDX\bin\icast.exe" OR TgtProcImagePath endswithCIS ":\Program Files\Citrix\System32\icast.exe") OR TgtProcImagePath IS NOT EMPTY OR (TgtProcCmdLine containsCIS "netlogon.bat" OR TgtProcCmdLine containsCIS "UsrLogon.cmd") OR (TgtProcImagePath endswithCIS ":\Windows\System32\proquota.exe" OR TgtProcImagePath endswithCIS ":\Windows\SysWOW64\proquota.exe") OR TgtProcCmdLine = "PowerShell.exe"))))

```