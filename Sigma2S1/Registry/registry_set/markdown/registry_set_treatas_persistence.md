# registry_set_treatas_persistence

## Title
COM Hijacking via TreatAs

## ID
dc5c24af-6995-49b2-86eb-a9ff62199e82

## Author
frack113

## Date
2022-08-28

## Tags
attack.persistence, attack.t1546.015

## Description
Detect modification of TreatAs key to enable "rundll32.exe -sta" command

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1546.015/T1546.015.md
https://www.youtube.com/watch?v=3gz1QmiMhss&t=1251s

## False Positives
Legitimate use

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "TreatAs\(Default)" AND (NOT ((SrcProcImagePath In Contains AnyCase ("C:\Windows\system32\msiexec.exe","C:\Windows\SysWOW64\msiexec.exe")) OR (SrcProcImagePath endswithCIS "\OfficeClickToRun.exe" AND SrcProcImagePath startswithCIS "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\") OR SrcProcImagePath = "C:\Program Files (x86)\Microsoft Office\root\integration\integrator.exe" OR SrcProcImagePath = "C:\Windows\system32\svchost.exe"))))

```