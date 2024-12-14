# proc_creation_win_xwizard_runwizard_com_object_exec

## Title
COM Object Execution via Xwizard.EXE

## ID
53d4bb30-3f36-4e8a-b078-69d36c4a79ff

## Author
Ensar Şamil, @sblmsrsn, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-10-07

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the execution of Xwizard tool with the "RunWizard" flag and a GUID like argument.
This utility can be abused in order to run custom COM object created in the registry.


## References
https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
https://www.elastic.co/guide/en/security/current/execution-of-com-object-via-xwizard.html
https://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine = "RunWizard" AND TgtProcCmdLine RegExp "\\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\\}"))

```