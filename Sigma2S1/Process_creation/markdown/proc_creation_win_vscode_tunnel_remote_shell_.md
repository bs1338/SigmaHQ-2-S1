# proc_creation_win_vscode_tunnel_remote_shell_

## Title
Visual Studio Code Tunnel Shell Execution

## ID
f4a623c2-4ef5-4c33-b811-0642f702c9f1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-10-25

## Tags
attack.command-and-control, attack.t1071.001

## Description
Detects the execution of a shell (powershell, bash, wsl...) via Visual Studio Code tunnel. Attackers can abuse this functionality to establish a C2 channel and execute arbitrary commands on the system.

## References
https://ipfyx.fr/post/visual-studio-code-tunnel/
https://badoption.eu/blog/2023/01/31/code_c2.html
https://code.visualstudio.com/docs/remote/tunnels

## False Positives
Legitimate use of Visual Studio Code tunnel and running code from there

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS ".vscode-server" AND SrcProcImagePath containsCIS "\servers\Stable-" AND SrcProcImagePath endswithCIS "\server\node.exe") AND ((TgtProcCmdLine containsCIS "\terminal\browser\media\shellIntegration.ps1" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) OR (TgtProcImagePath endswithCIS "\wsl.exe" OR TgtProcImagePath endswithCIS "\bash.exe"))))

```