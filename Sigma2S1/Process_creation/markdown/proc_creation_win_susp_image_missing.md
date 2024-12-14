# proc_creation_win_susp_image_missing

## Title
Execution Of Non-Existing File

## ID
71158e3f-df67-472b-930e-7d287acaa3e1

## Author
Max Altgelt (Nextron Systems)

## Date
2021-12-09

## Tags
attack.defense-evasion

## Description
Checks whether the image specified in a process creation event is not a full, absolute path (caused by process ghosting or other unorthodox methods to start a process)

## References
https://pentestlaboratories.com/2021/12/08/process-ghosting/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((NOT TgtProcImagePath containsCIS "\") AND (NOT (((TgtProcImagePath In Contains AnyCase ("System","Registry","MemCompression","vmmem")) OR (TgtProcCmdLine In Contains AnyCase ("Registry","MemCompression","vmmem"))) OR (TgtProcImagePath In Contains AnyCase ("-","")) OR TgtProcImagePath IS NOT EMPTY))))

```