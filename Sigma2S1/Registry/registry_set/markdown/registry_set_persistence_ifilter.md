# registry_set_persistence_ifilter

## Title
Register New IFiltre For Persistence

## ID
b23818c7-e575-4d13-8012-332075ec0a2b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker registers a new IFilter for an extension. Microsoft Windows Search uses filters to extract the content of items for inclusion in a full-text index.
You can extend Windows Search to index new or proprietary file types by writing filters to extract the content, and property handlers to extract the properties of files.


## References
https://persistence-info.github.io/Data/ifilters.html
https://twitter.com/0gtweet/status/1468548924600459267
https://github.com/gtworek/PSBits/tree/master/IFilter
https://github.com/gtworek/PSBits/blob/8d767892f3b17eefa4d0668f5d2df78e844f01d8/IFilter/Dll.cpp#L281-L308

## False Positives
Legitimate registration of IFilters by the OS or software

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryKeyPath containsCIS "\SOFTWARE\Classes\CLSID" AND RegistryKeyPath containsCIS "\PersistentAddinsRegistered\{89BCB740-6119-101A-BCB7-00DD010655AF}") OR (RegistryKeyPath containsCIS "\SOFTWARE\Classes\." AND RegistryKeyPath containsCIS "\PersistentHandler")) AND (NOT ((RegistryKeyPath containsCIS "\CLSID\{4F46F75F-199F-4C63-8B7D-86D48FE7970C}\" OR RegistryKeyPath containsCIS "\CLSID\{4887767F-7ADC-4983-B576-88FB643D6F79}\" OR RegistryKeyPath containsCIS "\CLSID\{D3B41FA1-01E3-49AF-AA25-1D0D824275AE}\" OR RegistryKeyPath containsCIS "\CLSID\{72773E1A-B711-4d8d-81FA-B9A43B0650DD}\" OR RegistryKeyPath containsCIS "\CLSID\{098f2470-bae0-11cd-b579-08002b30bfeb}\" OR RegistryKeyPath containsCIS "\CLSID\{1AA9BF05-9A97-48c1-BA28-D9DCE795E93C}\" OR RegistryKeyPath containsCIS "\CLSID\{2e2294a9-50d7-4fe7-a09f-e6492e185884}\" OR RegistryKeyPath containsCIS "\CLSID\{34CEAC8D-CBC0-4f77-B7B1-8A60CB6DA0F7}\" OR RegistryKeyPath containsCIS "\CLSID\{3B224B11-9363-407e-850F-C9E1FFACD8FB}\" OR RegistryKeyPath containsCIS "\CLSID\{3DDEB7A4-8ABF-4D82-B9EE-E1F4552E95BE}\" OR RegistryKeyPath containsCIS "\CLSID\{5645C8C1-E277-11CF-8FDA-00AA00A14F93}\" OR RegistryKeyPath containsCIS "\CLSID\{5645C8C4-E277-11CF-8FDA-00AA00A14F93}\" OR RegistryKeyPath containsCIS "\CLSID\{58A9EBF6-5755-4554-A67E-A2467AD1447B}\" OR RegistryKeyPath containsCIS "\CLSID\{5e941d80-bf96-11cd-b579-08002b30bfeb}\" OR RegistryKeyPath containsCIS "\CLSID\{698A4FFC-63A3-4E70-8F00-376AD29363FB}\" OR RegistryKeyPath containsCIS "\CLSID\{7E9D8D44-6926-426F-AA2B-217A819A5CCE}\" OR RegistryKeyPath containsCIS "\CLSID\{8CD34779-9F10-4f9b-ADFB-B3FAEABDAB5A}\" OR RegistryKeyPath containsCIS "\CLSID\{9694E38A-E081-46ac-99A0-8743C909ACB6}\" OR RegistryKeyPath containsCIS "\CLSID\{98de59a0-d175-11cd-a7bd-00006b827d94}\" OR RegistryKeyPath containsCIS "\CLSID\{AA10385A-F5AA-4EFF-B3DF-71B701E25E18}\" OR RegistryKeyPath containsCIS "\CLSID\{B4132098-7A03-423D-9463-163CB07C151F}\" OR RegistryKeyPath containsCIS "\CLSID\{d044309b-5da6-4633-b085-4ed02522e5a5}\" OR RegistryKeyPath containsCIS "\CLSID\{D169C14A-5148-4322-92C8-754FC9D018D8}\" OR RegistryKeyPath containsCIS "\CLSID\{DD75716E-B42E-4978-BB60-1497B92E30C4}\" OR RegistryKeyPath containsCIS "\CLSID\{E2F83EED-62DE-4A9F-9CD0-A1D40DCD13B6}\" OR RegistryKeyPath containsCIS "\CLSID\{E772CEB3-E203-4828-ADF1-765713D981B8}\" OR RegistryKeyPath containsCIS "\CLSID\{eec97550-47a9-11cf-b952-00aa0051fe20}" OR RegistryKeyPath containsCIS "\CLSID\{FB10BD80-A331-4e9e-9EB7-00279903AD99}\") OR (SrcProcImagePath startswithCIS "C:\Windows\System32\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\" OR SrcProcImagePath startswithCIS "C:\Program Files\")))))

```