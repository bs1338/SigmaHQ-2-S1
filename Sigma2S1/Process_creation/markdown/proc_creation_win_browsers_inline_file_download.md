# proc_creation_win_browsers_inline_file_download

## Title
File Download From Browser Process Via Inline URL

## ID
94771a71-ba41-4b6e-a757-b531372eaab6

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-11

## Tags
attack.command-and-control, attack.t1105

## Description
Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for example by launching the browser in a minimized state.

## References
https://twitter.com/mrd0x/status/1478116126005641220
https://lolbas-project.github.io/lolbas/Binaries/Msedge/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".7z" OR TgtProcCmdLine endswithCIS ".dat" OR TgtProcCmdLine endswithCIS ".dll" OR TgtProcCmdLine endswithCIS ".exe" OR TgtProcCmdLine endswithCIS ".hta" OR TgtProcCmdLine endswithCIS ".ps1" OR TgtProcCmdLine endswithCIS ".psm1" OR TgtProcCmdLine endswithCIS ".txt" OR TgtProcCmdLine endswithCIS ".vbe" OR TgtProcCmdLine endswithCIS ".vbs" OR TgtProcCmdLine endswithCIS ".zip") AND TgtProcCmdLine containsCIS "http" AND (TgtProcImagePath endswithCIS "\brave.exe" OR TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\opera.exe" OR TgtProcImagePath endswithCIS "\vivaldi.exe")))

```