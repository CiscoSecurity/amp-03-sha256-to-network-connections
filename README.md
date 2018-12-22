[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/AMP-for-Endpoints "Gitter chat")

### SHA256 to Network Connections:

This script searches an AMP for Endpoints environment for computers that have seen a SHA256, it then fetches their trajectory and parses out the observed network connections associated with that SHA256. You must provide a SHA256 as a command line argument.

NOTE: For use in large environments with over 3000 endpoints it is possible to hit the hourly API rate limit and not get a complete list.

### Before using you must update the following:
The authentictaion parameters are set in the ```api.cfg```
- client_id 
- api_key

### Usage:
```
python sha256_to_network_connections.py 438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7
```

### Example script output:
```
Computers found: 2
Querying: Demo_AMP_Intel - 14dcfce3-9663-434d-9beb-c8836de035ce
Querying: Demo_Command_Line_Arguments_Kovter - 9fc87138-e65a-48cf-85c2-f5b8834e2109
  UDP 192.168.23.113:63678 -> 55.223.148.141:1900
  TCP 192.168.23.113:50308 -> 72.15.55.186:443
  TCP 192.168.23.113:50306 -> 6.196.65.123:443
  TCP 192.168.23.113:50186 -> 208.156.236.132:443
  TCP 40.80.145.38:80 <- 204.65.35.152:50238
  UDP 192.168.23.113:51082 -> 63.196.22.179:53
  TCP 192.168.23.113:50263 -> 55.217.246.42:443
  UDP 192.168.23.113:58041 -> 32.207.154.156:53
```
