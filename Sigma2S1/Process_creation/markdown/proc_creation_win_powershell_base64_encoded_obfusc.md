# proc_creation_win_powershell_base64_encoded_obfusc

## Title
Suspicious Obfuscated PowerShell Code

## ID
8d01b53f-456f-48ee-90f6-bc28e67d4e35

## Author
Florian Roth (Nextron Systems)

## Date
2022-07-11

## Tags
attack.defense-evasion

## Description
Detects suspicious UTF16 and base64 encoded and often obfuscated PowerShell code often used in command lines

## References
https://app.any.run/tasks/fcadca91-3580-4ede-aff4-4d2bf809bf99/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "IAAtAGIAeABvAHIAIAAwAHgA" OR TgtProcCmdLine containsCIS "AALQBiAHgAbwByACAAMAB4A" OR TgtProcCmdLine containsCIS "gAC0AYgB4AG8AcgAgADAAeA" OR TgtProcCmdLine containsCIS "AC4ASQBuAHYAbwBrAGUAKAApACAAfAAg" OR TgtProcCmdLine containsCIS "AuAEkAbgB2AG8AawBlACgAKQAgAHwAI" OR TgtProcCmdLine containsCIS "ALgBJAG4AdgBvAGsAZQAoACkAIAB8AC" OR TgtProcCmdLine containsCIS "AHsAMQB9AHsAMAB9ACIAIAAtAGYAI" OR TgtProcCmdLine containsCIS "B7ADEAfQB7ADAAfQAiACAALQBmAC" OR TgtProcCmdLine containsCIS "AewAxAH0AewAwAH0AIgAgAC0AZgAg" OR TgtProcCmdLine containsCIS "AHsAMAB9AHsAMwB9ACIAIAAtAGYAI" OR TgtProcCmdLine containsCIS "B7ADAAfQB7ADMAfQAiACAALQBmAC" OR TgtProcCmdLine containsCIS "AewAwAH0AewAzAH0AIgAgAC0AZgAg" OR TgtProcCmdLine containsCIS "AHsAMgB9AHsAMAB9ACIAIAAtAGYAI" OR TgtProcCmdLine containsCIS "B7ADIAfQB7ADAAfQAiACAALQBmAC" OR TgtProcCmdLine containsCIS "AewAyAH0AewAwAH0AIgAgAC0AZgAg" OR TgtProcCmdLine containsCIS "AHsAMQB9AHsAMAB9ACcAIAAtAGYAI" OR TgtProcCmdLine containsCIS "B7ADEAfQB7ADAAfQAnACAALQBmAC" OR TgtProcCmdLine containsCIS "AewAxAH0AewAwAH0AJwAgAC0AZgAg" OR TgtProcCmdLine containsCIS "AHsAMAB9AHsAMwB9ACcAIAAtAGYAI" OR TgtProcCmdLine containsCIS "B7ADAAfQB7ADMAfQAnACAALQBmAC" OR TgtProcCmdLine containsCIS "AewAwAH0AewAzAH0AJwAgAC0AZgAg" OR TgtProcCmdLine containsCIS "AHsAMgB9AHsAMAB9ACcAIAAtAGYAI" OR TgtProcCmdLine containsCIS "B7ADIAfQB7ADAAfQAnACAALQBmAC" OR TgtProcCmdLine containsCIS "AewAyAH0AewAwAH0AJwAgAC0AZgAg"))

```