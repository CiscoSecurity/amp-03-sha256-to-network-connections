### SHA256 to Network Connections

Sample script for searching an environment for computers that have seen a SHA256 and outputing network connections generated by that SHA256.

### Usage
This script reads the API credentials from an api.cfg file, client_id and api_key must be entered there prior to running the script.

To use this script you provide a SHA256 as a command line paramter:
'''
python sha256_to_network_connections.py a253ae6f8fb5733319545b34f3bc1266463c2b40c67bcbbf33a089f82ffd73d0
'''

For use in large environments with over 3000 endpoints it is possible to hit the hourly API rate limit and not get a complete list.
