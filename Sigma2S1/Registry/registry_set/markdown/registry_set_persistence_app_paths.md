# registry_set_persistence_app_paths

## Title
Potential Persistence Via App Paths Default Property

## ID
707e097c-e20f-4f67-8807-1f72ff4500d6

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-10

## Tags
attack.persistence, attack.t1546.012

## Description
Detects changes to the "Default" property for keys located in the \Software\Microsoft\Windows\CurrentVersion\App Paths\ registry. Which might be used as a method of persistence
The entries found under App Paths are used primarily for the following purposes.
First, to map an application's executable file name to that file's fully qualified path.
Second, to prepend information to the PATH environment variable on a per-application, per-process basis.


## References
https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/
https://learn.microsoft.com/en-us/windows/win32/shell/app-registration

## False Positives
Legitimate applications registering their binary from on of the suspicious locations mentioned above (tune it)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS "\Users\Public" OR RegistryValue containsCIS "\AppData\Local\Temp\" OR RegistryValue containsCIS "\Windows\Temp\" OR RegistryValue containsCIS "\Desktop\" OR RegistryValue containsCIS "\Downloads\" OR RegistryValue containsCIS "%temp%" OR RegistryValue containsCIS "%tmp%" OR RegistryValue containsCIS "iex" OR RegistryValue containsCIS "Invoke-" OR RegistryValue containsCIS "rundll32" OR RegistryValue containsCIS "regsvr32" OR RegistryValue containsCIS "mshta" OR RegistryValue containsCIS "cscript" OR RegistryValue containsCIS "wscript" OR RegistryValue containsCIS ".bat" OR RegistryValue containsCIS ".hta" OR RegistryValue containsCIS ".dll" OR RegistryValue containsCIS ".ps1") AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" AND (RegistryKeyPath endswithCIS "(Default)" OR RegistryKeyPath endswithCIS "Path")))

```