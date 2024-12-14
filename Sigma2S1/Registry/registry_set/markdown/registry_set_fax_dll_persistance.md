# registry_set_fax_dll_persistance

## Title
Change the Fax Dll

## ID
9e3357ba-09d4-4fbd-a7c5-ad6386314513

## Author
frack113

## Date
2022-07-17

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect possible persistence using Fax DLL load when service restart

## References
https://twitter.com/dottor_morte/status/1544652325570191361
https://raw.githubusercontent.com/RiccardoAncarani/talks/master/F-Secure/unorthodox-lateral-movement.pdf

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Software\Microsoft\Fax\Device Providers\" AND RegistryKeyPath containsCIS "\ImageName") AND (NOT RegistryValue = "%systemroot%\system32\fxst30.dll")))

```