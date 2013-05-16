#!/bin/bash 
#	Created By @tekguy
#	20130516
privateKeyFileName="private.key"
certficateFileName="certificate.cer"
pfxFileName="certificate.pfx"

#remove files
rm $privateKeyFileName
rm $certficateFileName
rm $pfxFileName

# Generate the private key
openssl genrsa -out $privateKeyFileName 1024
# Generate the certificate, X509 with 1048 encryption
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout $privateKeyFileName -out $certficateFileName
# Combine key and cert to create a PFX file
openssl pkcs12 -export -in $certficateFileName -inkey $privateKeyFileName  -out $pfxFileName