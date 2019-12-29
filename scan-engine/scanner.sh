#!/bin/sh
# Sadly this is necessary as it's difficult to use ARM/ARM64 with CI systems currently
apk add --no-cache nmap nmap-scripts git

mkdir .nmap

git clone https://github.com/vulnersCom/nmap-vulners .nmap

nmap --datadir .nmap --script-updatedb

/go/bin/scan-engine
