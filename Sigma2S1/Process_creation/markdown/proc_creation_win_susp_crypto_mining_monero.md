# proc_creation_win_susp_crypto_mining_monero

## Title
Potential Crypto Mining Activity

## ID
66c3b204-9f88-4d0a-a7f7-8a57d521ca55

## Author
Florian Roth (Nextron Systems)

## Date
2021-10-26

## Tags
attack.impact, attack.t1496

## Description
Detects command line parameters or strings often used by crypto miners

## References
https://www.poolwatch.io/coin/monero

## False Positives
Legitimate use of crypto miners
Some build frameworks

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " --cpu-priority=" OR TgtProcCmdLine containsCIS "--donate-level=0" OR TgtProcCmdLine containsCIS " -o pool." OR TgtProcCmdLine containsCIS " --nicehash" OR TgtProcCmdLine containsCIS " --algo=rx/0 " OR TgtProcCmdLine containsCIS "stratum+tcp://" OR TgtProcCmdLine containsCIS "stratum+udp://" OR TgtProcCmdLine containsCIS "LS1kb25hdGUtbGV2ZWw9" OR TgtProcCmdLine containsCIS "0tZG9uYXRlLWxldmVsP" OR TgtProcCmdLine containsCIS "tLWRvbmF0ZS1sZXZlbD" OR TgtProcCmdLine containsCIS "c3RyYXR1bSt0Y3A6Ly" OR TgtProcCmdLine containsCIS "N0cmF0dW0rdGNwOi8v" OR TgtProcCmdLine containsCIS "zdHJhdHVtK3RjcDovL" OR TgtProcCmdLine containsCIS "c3RyYXR1bSt1ZHA6Ly" OR TgtProcCmdLine containsCIS "N0cmF0dW0rdWRwOi8v" OR TgtProcCmdLine containsCIS "zdHJhdHVtK3VkcDovL") AND (NOT (TgtProcCmdLine containsCIS " pool.c " OR TgtProcCmdLine containsCIS " pool.o " OR TgtProcCmdLine containsCIS "gcc -"))))

```