# proc_creation_win_tapinstall_execution

## Title
Tap Installer Execution

## ID
99793437-3e16-439b-be0f-078782cf953d

## Author
Daniil Yugoslavskiy, Ian Davis, oscd.community

## Date
2019-10-24

## Tags
attack.exfiltration, attack.t1048

## Description
Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques

## References
https://community.openvpn.net/openvpn/wiki/ManagingWindowsTAPDrivers

## False Positives
Legitimate OpenVPN TAP installation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\tapinstall.exe" AND (NOT ((TgtProcImagePath containsCIS ":\Program Files\Avast Software\SecureLine VPN\" OR TgtProcImagePath containsCIS ":\Program Files (x86)\Avast Software\SecureLine VPN\") OR TgtProcImagePath containsCIS ":\Program Files\OpenVPN Connect\drivers\tap\" OR TgtProcImagePath containsCIS ":\Program Files (x86)\Proton Technologies\ProtonVPNTap\installer\"))))

```