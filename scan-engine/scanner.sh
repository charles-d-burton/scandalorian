#!/bin/sh

apk add --no-cache nmap nmap-scripts git

mkdir .nmap

git clone https://github.com/vulnersCom/nmap-vulners .nmap

nmap --datadir .nmap --script-updatedb

/go/bin/scan-engine
