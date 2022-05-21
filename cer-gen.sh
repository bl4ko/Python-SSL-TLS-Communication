#!/bin/bash

# certificate generator for SSL/TLS communication

#Required
domain="$1"
commonname="$domain"

#Change to your company details
country="SI"
state=""
locality=""
organization=""
organizationalunit=""

#Optional
password=""

if [ -z "$domain" ]
then
    echo "Argument not present."
    echo "Usage $0 [common name]"

    exit 128 
fi

echo "Generating key request for $domain"

# Generate Public/Private keys
openssl req \
    -newkey rsa:2048 -x509 -days 365 -nodes -sha256  \
    -keyout "$domain".key \
    -out "$domain".crt \
    -passin pass:"$password" \
    -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname" 

# Add a public key to server certs
cat "$domain".crt >> clients.pem

echo "Successfully generated keys for $domain"
