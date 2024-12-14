# proc_creation_win_remote_access_tools_screenconnect_remote_execution_susp

## Title
Remote Access Tool - ScreenConnect Potential Suspicious Remote Command Execution

## ID
7b582f1a-b318-4c6a-bf4e-66fe49bf55a5

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), @Kostastsale

## Date
2022-02-25

## Tags
attack.command-and-control, attack.t1219

## Description
Detects potentially suspicious child processes launched via the ScreenConnect client service.


## References
https://www.mandiant.com/resources/telegram-malware-iranian-espionage
https://docs.connectwise.com/ConnectWise_Control_Documentation/Get_started/Host_client/View_menu/Backstage_mode
https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html

## False Positives
If the script being executed make use of any of the utilities mentioned in the detection then they should filtered out or allowed.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcImagePath endswithCIS "\dllhost.exe" OR TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\nltest.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wevtutil.exe") AND (SrcProcCmdLine containsCIS ":\Windows\TEMP\ScreenConnect\" AND SrcProcCmdLine containsCIS "run.cmd")))

```