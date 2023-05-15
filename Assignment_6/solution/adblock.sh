#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"

function domain_to_IP() {
	domainNamesFile=$1; # input file
	IPAddressesFile=$2; # output file

	while read line; do
		# Use Google's DNS 8.8.8.8 and repeat up to 3 times if there is a failure (because DNS uses UDP). Use A records for IPv4 addresses.
		# Skip the first 5 lines which are the DNS description, stick with the rest lines.
		# Match the IP string format using grep. There may be many IP addresses, all of them will be found.
		# Write to both output file (append) and stdout for better interraction.
		# Execute each DNS query in the background.
		host -t A -R 3 $line 8.8.8.8 | tail -n +6 | grep -o -E '([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}' | tee -a $IPAddressesFile &
	done < $domainNamesFile
}

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi

	if [ "$1" = "-domains"  ]; then
		# Find different and same domains in ‘domainNames.txt’ and ‘domainNames2.txt’ files 
		# and write them in “IPAddressesDifferent.txt and IPAddressesSame.txt" respectively

		# These two files contain the same and the different domain names which
		# are requested to find their correspoding IP addresses.
		domainNamesSame='domainNamesSame.txt';
		domainNamesDifferent='domainNamesDifferent.txt';

		# Truncate the following files in order to create them afresh
		truncate -s 0 $domainNamesSame
		truncate -s 0 $domainNamesDifferent
		truncate -s 0 $IPAddressesSame
		truncate -s 0 $IPAddressesDifferent

		# Find the common addresses and write them to the output file
		grep -sf $domainNames $domainNames2 > $domainNamesSame

		# Find the addresses that are in the first file but not in the second one and write them to the output file
		grep -svf $domainNames2 $domainNames2 > $domainNamesDifferent

		# Find the addresses that are in the second file but not in the first one and append them to the output file
		grep -svf $domainNames $domainNames2 >> $domainNamesDifferent

		# Convert the same domain names to IP addresses
		domain_to_IP $domainNamesSame $IPAddressesSame

		# Convert the different domain names to IP addresses
		domain_to_IP $domainNamesDifferent $IPAddressesDifferent

		wait # wait for the background host jobs to finish

        true
            
    elif [ "$1" = "-ipssame"  ]; then
        # Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.
		while read line; do
			iptables -I INPUT -j DROP -s $line
		done < $IPAddressesSame

        true

    elif [ "$1" = "-ipsdiff"  ]; then
        # Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.
		while read line; do
			iptables -I INPUT -j REJECT -s $line
		done < $IPAddressesDifferent

        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file. First, truncate the file in case it already has content in it.
		truncate -s 0 $adblockRules
		iptables-save -f $adblockRules
		
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
		iptables-restore $adblockRules

        true
        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
		iptables -F
		iptables -P INPUT ACCEPT
		iptables -P FORWARD ACCEPT
		iptables -P OUTPUT ACCEPT

        true
        
    elif [ "$1" = "-list"  ]; then
        # List current rules. Use -n option in order to avoid long reverse DNS lookups.
		iptables -nL

        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
        printf "  -ipsdiff\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
