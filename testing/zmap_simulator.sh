#!/bin/bash

# Number of IP addresses to generate
NUM_ADDRESSES=1000000
# Output file
OUTPUT_FILE="/data/ipv4/test.txt"

# Clear the file if it already exists
> $OUTPUT_FILE

# Generate random IP addresses
for ((i = 1; i <= NUM_ADDRESSES; i++))
do
    # Generate each octet
    OCTET1=$((RANDOM % 256))
    OCTET2=$((RANDOM % 256))
    OCTET3=$((RANDOM % 256))
    OCTET4=$((RANDOM % 256))

    # Form the IP address
    IP_ADDRESS="$OCTET1.$OCTET2.$OCTET3.$OCTET4"

    # Write the IP address to the output file
    echo $IP_ADDRESS >> $OUTPUT_FILE
done

echo "Generated $NUM_ADDRESSES IP addresses and saved them to $OUTPUT_FILE"
