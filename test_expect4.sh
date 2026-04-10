#!/usr/bin/expect
spawn ./yeet.sh upload test_key7 test_upload2
expect "Enter old passphrase:"
send "mypass\r"
expect eof
