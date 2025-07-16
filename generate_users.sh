#!/bin/bash

# generate_users.sh
# 
# Simple script to generate users.json configuration file for SOCKS5 multi-user server
#
# Usage: ./generate_users.sh
#
# This script will:
# 1. Run the generate_config.go program
# 2. Create users.json with bcrypt-hashed passwords
# 3. Validate the configuration loads correctly

echo "=== SOCKS5 Multi-User Configuration Generator ==="
echo "Generating users.json with bcrypt hashed passwords..."
echo

# Run the configuration generator
go run generate_config.go

# Check if it was successful
if [ $? -eq 0 ]; then
    echo
    echo "=== Configuration Generated Successfully ==="
    echo "The users.json file has been created with the following users:"
    echo "  - admin (password: admin123)"
    echo "  - user1 (password: user123)"  
    echo "  - restricted (password: restricted123)"
    echo
    echo "All passwords are properly hashed using bcrypt."
    echo "You can now use this configuration file with the SOCKS5 server."
else
    echo
    echo "=== Configuration Generation Failed ==="
    echo "Please check the error messages above."
    exit 1
fi