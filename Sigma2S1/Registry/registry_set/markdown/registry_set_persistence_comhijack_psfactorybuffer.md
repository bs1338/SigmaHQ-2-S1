# registry_set_persistence_comhijack_psfactorybuffer

## Title
Potential PSFactoryBuffer COM Hijacking

## ID
243380fa-11eb-4141-af92-e14925e77c1b

## Author
BlackBerry Threat Research and Intelligence Team - @Joseliyo_Jstnk

## Date
2023-06-07

## Tags
attack.persistence, attack.t1546.015

## Description
Detects changes to the PSFactory COM InProcServer32 registry. This technique was used by RomCom to create persistence storing a malicious DLL.

## References
https://blogs.blackberry.com/en/2023/06/romcom-resurfaces-targeting-ukraine
https://strontic.github.io/xcyclopedia/library/clsid_C90250F3-4D7D-4991-9B69-A5C5BC1C2AE6.html
https://www.virustotal.com/gui/file/6d3ab9e729bb03ae8ae3fcd824474c5052a165de6cb4c27334969a542c7b261d/detection
https://www.trendmicro.com/en_us/research/23/e/void-rabisu-s-use-of-romcom-backdoor-shows-a-growing-shift-in-th.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\CLSID\{c90250f3-4d7d-4991-9b69-a5c5bc1c2ae6}\InProcServer32\(Default)" AND (NOT (RegistryValue In Contains AnyCase ("%windir%\System32\ActXPrxy.dll","C:\Windows\System32\ActXPrxy.dll")))))

```