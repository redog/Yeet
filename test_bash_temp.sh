#!/bin/bash
key_file="test_key2"
temp_key=$(mktemp)
cp "$key_file" "$temp_key"
chmod 600 "$temp_key"
ssh-keygen -p -f "$temp_key" -N ""
echo $?
rm "$temp_key"
