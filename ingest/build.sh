#!/bin/bash
export PCAPV=1.9.1
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar xvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=arm-linux-gnueabi-gcc
./configure --host=arm-linux --with-pcap=linux
make

cd ..
env CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L./libpcap-$PCAPV" go build -o ingest-arm .
file ingest-arm

rm -rf libpcap-$PCAPV
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar xvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=aarch64-linux-gnu-gcc
export CFLAGS='-Os'
./configure --host=aarch64-unknown-linux-gnu --with-pcap=linux
cat config.log
make


cd ..
env CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CGO_LDFLAGS="-L./libpcap-$PCAPV" go build -o ingest-arm64 .
file ingest-arm64

env CC=gcc CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ingest-amd64 .

file ingest-amd64
