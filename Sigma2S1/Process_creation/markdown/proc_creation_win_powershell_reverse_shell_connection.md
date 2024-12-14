# proc_creation_win_powershell_reverse_shell_connection

## Title
Potential Powershell ReverseShell Connection

## ID
edc2f8ae-2412-4dfd-b9d5-0c57727e70be

## Author
FPT.EagleEye, wagga, Nasreddine Bencherchali (Nextron Systems)

## Date
2021-03-03

## Tags
attack.execution, attack.t1059.001

## Description
Detects usage of the "TcpClient" class. Which can be abused to establish remote connections and reverse-shells. As seen used by the Nishang "Invoke-PowerShellTcpOneLine" reverse shell and other.

## References
https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Shells/Invoke-PowerShellTcpOneLine.ps1

## False Positives
In rare administrative cases, this function might be used to check network connectivity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " Net.Sockets.TCPClient" AND TgtProcCmdLine containsCIS ".GetStream(" AND TgtProcCmdLine containsCIS ".Write(") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```