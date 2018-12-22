import sys
import configparser
import requests

# Specify the config file
configFile = 'api.cfg'

# Reading the config file to get settings
config = configparser.RawConfigParser()
config.read(configFile)
client_id = config.get('AMPE', 'client_id')
api_key = config.get('AMPE', 'api_key')

# Validate a command line parameter was provided
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s 438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7' % sys.argv[0])

# Store the command line parameter
process_sha256 = sys.argv[1]

# Containers for output
computer_guids = {}
remote_ips = {}

# Creat session object
# http://docs.python-requests.org/en/master/user/advanced/
# Using a session object gains efficiency when making multiple requests
s = requests.Session()
s.auth = (client_id, api_key)

# Define URL and parameters
activity_url = 'https://api.amp.cisco.com/v1/computers/activity'
q = process_sha256
payload = {'q': q}

# Query API
r = s.get(activity_url, params=payload)

# Decode JSON response
query = r.json()

# Name data section of JSON
data = query['data']

# Store unique connector GUIDs and hostnames
for entry in data:
    if entry['connector_guid'] not in computer_guids:
        connector_guid = entry['connector_guid']
        hostname = entry['hostname']
        computer_guids[connector_guid] = {'hostname':hostname}

print('Computers found: {}'.format(len(computer_guids)))

# Query trajectory for each GUID 
for guid in computer_guids:

    # Print the hostname and GUID that is about to be queried
    print('Querying: {} - {}'.format(computer_guids[guid]['hostname'],guid))

    payload = {'q' : process_sha256}
    url = 'https://api.amp.cisco.com/v1/computers/{}/trajectory'.format(guid)
    r = s.get(url, auth=(client_id,api_key), params=payload)

    # # Decode JSON response 
    query = r.json()

    # Name events section of JSON
    events = query['data']['events']

    # Parse trajectory events to find the network events
    for event in events:
        event_type = event['event_type']

        # Extract IPs from NFM (Network Flow Monitor) events
        if event_type == 'NFM':
            network_info = event['network_info']
            protocol = network_info['nfm']['protocol']
            local_ip = network_info['local_ip']
            local_port = network_info['local_port']
            remote_ip = network_info['remote_ip']
            remote_port = network_info['remote_port']
            direction = network_info['nfm']['direction']

            # Store unique remote IP and create structure to store remote port
            if remote_ip not in remote_ips:
                remote_ips[remote_ip] = {'ports':[]}

            # Store unique remote port 
            if remote_port not in remote_ips[remote_ip]['ports']:
                remote_ips[remote_ip]['ports'].append(remote_port)

            # Print information for outgoing connection
            if direction == 'Outgoing connection from':
                print('  {} {}:{} -> {}:{}'.format(protocol,local_ip,local_port,remote_ip,remote_port))

            # Print information for incoming connection
            if direction == 'Incoming connection from':
                print('  {} {}:{} <- {}:{}'.format(protocol,local_ip,local_port,remote_ip,remote_port))

        # Parse DFC (Device Flow Correlation) events
        if event_type == 'DFC Threat Detected':
            network_info = event['network_info']
            local_ip = network_info['local_ip']
            local_port = network_info['local_port']
            remote_ip = network_info['remote_ip']
            remote_port = network_info['remote_port']

            # Store unique remote IP and create structure to store remote port
            if remote_ip not in remote_ips:
                remote_ips[remote_ip] = {'ports':[]}

            # Store unique remote port 
            if remote_port not in remote_ips[remote_ip]['ports']:
                remote_ips[remote_ip]['ports'].append(remote_port)

            # Print information for communication between two hosts (DFC events do not indicate direction)
            print('  N/A {}:{} - {}:{}'.format(local_ip,local_port,remote_ip,remote_port))

# If IPs were found, write them to a CSV file
if len(remote_ips) > 0:
    print('Writing {}_remote_ips.csv'.format(process_sha256))
    with open('{}_remote_ips.csv'.format(process_sha256),'w') as f:
        for ip in remote_ips:
            for port in remote_ips[ip]['ports']:
                f.write('{},{}\n'.format(ip,port))
else:
    print('No network traffic observed by AMP for Endpoint')
    