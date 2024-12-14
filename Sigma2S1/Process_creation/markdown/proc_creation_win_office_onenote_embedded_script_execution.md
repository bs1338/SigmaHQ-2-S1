# proc_creation_win_office_onenote_embedded_script_execution

## Title
OneNote.EXE Execution of Malicious Embedded Scripts

## ID
84b1706c-932a-44c4-ae28-892b28a25b94

## Author
@kostastsale

## Date
2023-02-02

## Tags
attack.defense-evasion, attack.t1218.001

## Description
Detects the execution of malicious OneNote documents that contain embedded scripts.
When a user clicks on a OneNote attachment and then on the malicious link inside the ".one" file, it exports and executes the malicious embedded script from specific directories.


## References
https://bazaar.abuse.ch/browse/tag/one/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\exported\" OR TgtProcCmdLine containsCIS "\onenoteofflinecache_files\") AND (TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\onenote.exe"))

```