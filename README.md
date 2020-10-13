
# NetSec ETHZ Project 1: ACME Client

## Install

1. Set up Go and your `$GOPATH` 
2. `go get -u github.com/letsencrypt/pebble/...`
3. `cd $GOPATH/src/github.com/letsencrypt/pebble && go install ./...`
4. `pebble -h`

## Setup

Start the Pebble server `pebble -config ./test/config/pebble-config.json`
