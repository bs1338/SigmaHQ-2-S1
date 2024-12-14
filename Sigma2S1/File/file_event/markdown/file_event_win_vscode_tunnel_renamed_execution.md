# file_event_win_vscode_tunnel_renamed_execution

## Title
Renamed VsCode Code Tunnel Execution - File Indicator

## ID
d102b8f5-61dc-4e68-bd83-9a3187c67377

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-10-25

## Tags
attack.command-and-control

## Description
Detects the creation of a file with the name "code_tunnel.json" which indicate execution and usage of VsCode tunneling utility by an "Image" or "Process" other than VsCode.


## References
https://ipfyx.fr/post/visual-studio-code-tunnel/
https://badoption.eu/blog/2023/01/31/code_c2.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\code_tunnel.json" AND (NOT (SrcProcImagePath endswithCIS "\code-tunnel.exe" OR SrcProcImagePath endswithCIS "\code.exe"))))

```