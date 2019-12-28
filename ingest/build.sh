#!/bin/bash

cd /tmp
export PCAPV=1.9.1
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar xvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=arm-linux-gnueabi-gcc
./configure --host=arm-linux --with-pcap=linux
make

env CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L/tmp/libpcap-$PCAPV" go build -o ingest-arm .

