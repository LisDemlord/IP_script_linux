#!/bin/bash

function start_end_line() {
	echo -e "\033[1;32m=========================================================================================\033[0;0m"
}
function separator_line() {
	echo -e "\033[1;36m------------------------------------------------------------------------\033[0;0m"
}

start_end_line
separator_line

echo -e "CURRENT IPTABLES:\n"
iptables -L

# Enable strict error checking
set -o errexit
set -o nounset
set -o pipefail

# Set default policies for INPUT and OUTPUT chains
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

# Clear all rules
iptables -F

# Clear all user-defined chains
iptables -X

# Clear all byte counters
iptables -Z

# Flush and destroy all IP sets
ipset flush
ipset destroy
separator_line

separator_line
# Allow related and established connections, loopback traffic, drop invalid packets, and allow ICMP traffic
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p icmp -j ACCEPT
echo -e "BASIC CHANGE IPTABLES:\n"
iptables -L
separator_line

separator_line
echo -e "CHANGE DEFAULT POLICY (INPUT):\n"
iptables -P INPUT DROP
iptables -L
separator_line

separator_line
# Query process_open_sockets table to get information about open sockets
IP_TABLE=$(echo "SELECT (
  CASE family 
  WHEN 2 THEN 'IP4' 
  ELSE family END
) AS family, (
  CASE protocol 
  WHEN 6 THEN 'TCP' 
  WHEN 17 THEN 'UDP' 
  ELSE protocol END
) AS protocol, local_address, local_port, 
  remote_address
FROM process_open_sockets 
WHERE family IN (2) 
AND protocol IN (6, 17) 
LIMIT 4;" | osqueryi --json)
echo -e "TABLE OF OPEN CONNECTIONS:\n"
echo "$IP_TABLE"
separator_line

separator_line
# Extract protocol information from the query result
IP_ROW=$(echo "$IP_TABLE" | jq -r '.[]')
IP_ROW=$(echo "$IP_ROW" | awk '{print $2}')
IP_ROW=$(echo "$IP_ROW" | tr -d '",')
echo -e "CONVERTED DATA:\n"
echo "$IP_ROW"
separator_line

separator_line
# Count the number of lines in the extracted information
LINE_COUNT=$(echo "$IP_ROW" | wc -l)
echo "NUMBER OF LINES = $LINE_COUNT"
separator_line

separator_line
# Initialize variables for storing IP version, protocol, local address, local port, and remote address
IP_VER=
PROTOCOL=
LOCAL_ADDRESS=
LOCAL_PORT=
REMOTE_ADDRESS=
COUNTER=2
NUM_CONNECT=1

# Iterate through each line of the extracted information
while [ $COUNTER -lt "$LINE_COUNT" ]
do
	echo -e "CONNECTION №$NUM_CONNECT:\n"

	# Extract and display IP version
	IP_VER=$(echo "$IP_ROW" | awk -v counter="$COUNTER" 'NR==counter')
	echo "IP VERSION = $IP_VER"
	((COUNTER++))

	# Extract and display local address
	LOCAL_ADDRESS=$(echo "$IP_ROW" | awk -v counter="$COUNTER" 'NR==counter')
        echo "LOCAL ADDRESS = $LOCAL_ADDRESS"
	((COUNTER++))
	
	# Extract and display local port
	LOCAL_PORT=$(echo "$IP_ROW" | awk -v counter="$COUNTER" 'NR==counter')
        echo "LOCAL PORT = $LOCAL_PORT"
	((COUNTER++))

	# Extract and display protocol
	PROTOCOL=$(echo "$IP_ROW" | awk -v counter="$COUNTER" 'NR==counter')
        echo "PROTOCOL = $PROTOCOL"
        ((COUNTER++))

	# Extract and display remote address
	REMOTE_ADDRESS=$(echo "$IP_ROW" | awk -v counter="$COUNTER" 'NR==counter')
        echo "REMOTE ADDRESS = $REMOTE_ADDRESS"
	((COUNTER+=3))
	
	# Add iptables rule to allow traffic based on extracted information
	iptables -A INPUT -p "$PROTOCOL" --dport "$LOCAL_PORT" -s "$REMOTE_ADDRESS" -d "$LOCAL_ADDRESS" -j ACCEPT
	
	echo -e "\nTHE RULE HAS BEEN ADDED"
	((NUM_CONNECT++))
	echo -e "\033[1;36m++++++++++++++++++++++++++++++++++++++++++++\033[0;0m"
done
separator_line

separator_line
echo -e "FINAL TABLE"
iptables -L

separator_line
touch iptables_options.rules
echo "THE SAVE FILE HAS BEEN CREATED: iptables_options.rules"
iptables-save > iptables_options.rules
echo -e "\nTHE RULES WAS SAVED"
separator_line

separator_line

echo -e "\nCOMPLETE!\n"

start_end_line
