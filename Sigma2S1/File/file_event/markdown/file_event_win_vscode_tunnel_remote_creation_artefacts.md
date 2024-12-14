# file_event_win_vscode_tunnel_remote_creation_artefacts

## Title
Visual Studio Code Tunnel Remote File Creation

## ID
56e05d41-ce99-4ecd-912d-93f019ee0b71

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-10-25

## Tags
attack.command-and-control

## Description
Detects the creation of file by the "node.exe" process in the ".vscode-server" directory. Could be a sign of remote file creation via VsCode tunnel feature


## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath containsCIS "\servers\Stable-" AND SrcProcImagePath endswithCIS "\server\node.exe" AND TgtFilePath containsCIS "\.vscode-server\data\User\History\"))

```