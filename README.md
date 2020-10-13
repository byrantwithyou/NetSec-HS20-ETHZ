
# NetSec ETHZ Project 1: ACME Client

My solutions to the Network Security Course AS20 taught at ETH Zurich. The Task was to implement an ACMEv2 client from scratch using only standard libraries. The ACME client communicates with an already existing ACME server (or the Pebble testing server) in order to obtain and manage SSL certificates.

## Application Components
This application consists of the following components:
* ACME client: An ACME client which can interact with a standard-conforming ACME server.
* DNS server: A DNS server which resolves the DNS queries of the ACME server.
* Challenge HTTP server: An HTTP server to respond to http-01 queries of the ACME server.
* Certificate HTTPS server: An HTTPS server which uses a certificate obtained by the ACME client.
* Shutdown HTTP server:  An HTTP server to receive a shutdown signal.

## Functionality
* use the ACME protocol to request and obtain certificates using the dns-01 and http-01 challenge,
* request and obtain certificates which contain aliases,
* request and obtain certificates with wildcard domain names, and
* revoke certificates after they have been issued by the ACME server.

## Background
Public Key Infrastructures (PKIs) using X.509 certificates are used for many purposes, the most significant of which is the authentication of domain names. Certificate Authorities (CAs) are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate. Traditionally, this verification is done through various ad-hoc methods.
The Automatic Certificate Management Environment (ACME) protocol aims to facilitate the automation of certificate issuance by creating a standardized and machine-friendly protocol for certificate management.
More information about ACME and relevant background can be found in RFC8555.

## Install

1. Set up Go and your `$GOPATH` 
2. `go get -u github.com/letsencrypt/pebble/...`
3. `cd $GOPATH/src/github.com/letsencrypt/pebble && go install ./...`
4. `pebble -h`

## Setup

Start the Pebble server `pebble -config ./test/config/pebble-config.json`
