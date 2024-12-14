# proc_creation_win_susp_web_request_cmd_and_cmdlets

## Title
Usage Of Web Request Commands And Cmdlets

## ID
9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d

## Author
James Pemberton / @4A616D6573, Endgame, JHasenbusch, oscd.community, Austin Songer @austinsonger

## Date
2019-10-24

## Tags
attack.execution, attack.t1059.001

## Description
Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via CommandLine

## References
https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
https://learn.microsoft.com/en-us/powershell/module/bitstransfer/add-bitsfile?view=windowsserver2019-ps

## False Positives
Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "[System.Net.WebRequest]::create" OR TgtProcCmdLine containsCIS "curl " OR TgtProcCmdLine containsCIS "Invoke-RestMethod" OR TgtProcCmdLine containsCIS "Invoke-WebRequest" OR TgtProcCmdLine containsCIS "iwr " OR TgtProcCmdLine containsCIS "Net.WebClient" OR TgtProcCmdLine containsCIS "Resume-BitsTransfer" OR TgtProcCmdLine containsCIS "Start-BitsTransfer" OR TgtProcCmdLine containsCIS "wget " OR TgtProcCmdLine containsCIS "WinHttp.WinHttpRequest"))

```