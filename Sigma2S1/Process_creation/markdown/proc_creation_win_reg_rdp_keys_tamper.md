# proc_creation_win_reg_rdp_keys_tamper

## Title
Potential Tampering With RDP Related Registry Keys Via Reg.EXE

## ID
0d5675be-bc88-4172-86d3-1e96a4476536

## Author
pH-T (Nextron Systems), @Kostastsale, @TheDFIRReport

## Date
2022-02-12

## Tags
attack.defense-evasion, attack.lateral-movement, attack.t1021.001, attack.t1112

## Description
Detects the execution of "reg.exe" for enabling/disabling the RDP service on the host by tampering with the 'CurrentControlSet\Control\Terminal Server' values

## References
https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " add " AND TgtProcCmdLine containsCIS "\CurrentControlSet\Control\Terminal Server" AND TgtProcCmdLine containsCIS "REG_DWORD" AND TgtProcCmdLine containsCIS " /f") AND TgtProcImagePath endswithCIS "\reg.exe") AND ((TgtProcCmdLine containsCIS "Licensing Core" AND TgtProcCmdLine containsCIS "EnableConcurrentSessions") OR (TgtProcCmdLine containsCIS "WinStations\RDP-Tcp" OR TgtProcCmdLine containsCIS "MaxInstanceCount" OR TgtProcCmdLine containsCIS "fEnableWinStation" OR TgtProcCmdLine containsCIS "TSUserEnabled" OR TgtProcCmdLine containsCIS "TSEnabled" OR TgtProcCmdLine containsCIS "TSAppCompat" OR TgtProcCmdLine containsCIS "IdleWinStationPoolCount" OR TgtProcCmdLine containsCIS "TSAdvertise" OR TgtProcCmdLine containsCIS "AllowTSConnections" OR TgtProcCmdLine containsCIS "fSingleSessionPerUser" OR TgtProcCmdLine containsCIS "fDenyTSConnections"))))

```