#!/bin/bash
key_file="test_rsa3"
temp_key=$(mktemp)
cp "$key_file" "$temp_key"
chmod 600 "$temp_key"
ssh-keygen -p -m openssh -f "$temp_key" -N ""
cat "$temp_key" | head -n 3
rm -f "$temp_key"
