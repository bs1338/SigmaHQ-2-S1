# registry_event_susp_mic_cam_access

## Title
Suspicious Camera and Microphone Access

## ID
62120148-6b7a-42be-8b91-271c04e281a3

## Author
Den Iuzvyk

## Date
2020-06-07

## Tags
attack.collection, attack.t1125, attack.t1123

## Description
Detects Processes accessing the camera and microphone from suspicious folder

## References
https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072

## False Positives
Unlikely, there could be conferencing software running from a Temp folder accessing the devices

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\" AND RegistryKeyPath containsCIS "\NonPackaged") AND (RegistryKeyPath containsCIS "microphone" OR RegistryKeyPath containsCIS "webcam") AND (RegistryKeyPath containsCIS ":#Windows#Temp#" OR RegistryKeyPath containsCIS ":#$Recycle.bin#" OR RegistryKeyPath containsCIS ":#Temp#" OR RegistryKeyPath containsCIS ":#Users#Public#" OR RegistryKeyPath containsCIS ":#Users#Default#" OR RegistryKeyPath containsCIS ":#Users#Desktop#")))

```