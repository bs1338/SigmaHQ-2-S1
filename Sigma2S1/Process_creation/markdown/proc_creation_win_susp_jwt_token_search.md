# proc_creation_win_susp_jwt_token_search

## Title
Potentially Suspicious JWT Token Search Via CLI

## ID
6d3a3952-6530-44a3-8554-cf17c116c615

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-25

## Tags
attack.credential-access, attack.t1528

## Description
Detects possible search for JWT tokens via CLI by looking for the string "eyJ0eX" or "eyJhbG".
This string is used as an anchor to look for the start of the JWT token used by microsoft office and similar apps.


## References
https://mrd0x.com/stealing-tokens-from-office-applications/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "eyJ0eXAiOi" OR TgtProcCmdLine containsCIS "eyJhbGciOi" OR TgtProcCmdLine containsCIS " eyJ0eX" OR TgtProcCmdLine containsCIS " \"eyJ0eX\"" OR TgtProcCmdLine containsCIS " 'eyJ0eX'" OR TgtProcCmdLine containsCIS " eyJhbG" OR TgtProcCmdLine containsCIS " \"eyJhbG\"" OR TgtProcCmdLine containsCIS " 'eyJhbG'"))

```