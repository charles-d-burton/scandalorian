#!/bin/sh
# Sadly this is necessary as it's difficult to use ARM/ARM64 with CI systems currently
apk add --no-cache nmap nmap-scripts git

#git clone https://github.com/vulnersCom/nmap-vulners .nmap

#nmap -d --datadir .nmap --script-updatedb
git clone https://github.com/scipag/vulscan scipag_vulscan

#ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan  

/go/bin/scan-engine
