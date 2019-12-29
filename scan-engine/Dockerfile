FROM golang:latest as build-arm

RUN apt update && apt install -y \
		gcc-arm* \
		libc6-dev-armhf-cross\
        byacc flex \
        libpcap-dev \
        file unzip
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
ENV PCAPV=1.9.1
ENV CC=arm-linux-gnueabi-gcc
RUN wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz && \
    tar xvf libpcap-$PCAPV.tar.gz && \
    cd libpcap-$PCAPV && \
    ./configure --host=arm-linux --with-pcap=linux && \
    make
RUN cd /app && \
    CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L/app/libpcap-$PCAPV" go build -a -ldflags '-w -extldflags "-static"' -o scan-engine . && \
    file scan-engine
RUN wget https://github.com/kost/nmap-android/releases/download/v7.31/nmap-7.31-binaries-armeabi.zip && \
    unzip nmap-7.31-binaries-armeabi.zip

FROM golang:latest as build-arm64
RUN apt update && apt install -y \
        gcc-aarch64* \
        libc6-dev-arm64-cross\
        byacc flex \
        libpcap-dev \
        file unzip
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
ENV PCAPV=1.9.1
ENV CC=aarch64-linux-gnu-gcc
ENV CFLAGS='-Os'
RUN wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz && \
    tar xvf libpcap-$PCAPV.tar.gz && \
    cd libpcap-$PCAPV && \
    ./configure --host=aarch64-unknown-linux-gnu --with-pcap=linux && \
    make
RUN cd /app && \
    CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CGO_LDFLAGS="-L/app/libpcap-$PCAPV" go build -a -ldflags '-w -extldflags "-static"' -o scan-engine . && \
    file scan-engine
RUN wget https://github.com/kost/nmap-android/releases/download/v7.31/nmap-7.31-binaries-arm64-v8a.zip && \
    unzip nmap-7.31-binaries-arm64-v8a.zip


FROM golang:latest as build-amd64
RUN apt update && apt install -y \
        build-essential \
        byacc flex \
        libpcap-dev \
        file unzip
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
ENV PCAPV=1.9.1
ENV CC=gcc
ENV CFLAGS='-Os'
RUN wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz && \
    tar xvf libpcap-$PCAPV.tar.gz && \
    cd libpcap-$PCAPV && \
    ./configure --with-pcap=linux && \
    make
RUN cd /app && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CGO_LDFLAGS="-L/app/libpcap-$PCAPV" go build -a -ldflags '-w -extldflags "-static"' -o scan-engine . && \
    file scan-engine
RUN wget https://github.com/kost/nmap-android/releases/download/v7.31/nmap-7.31-binaries-x86_64.zip && \
    unzip nmap-7.31-binaries-x86_64.zip



FROM arm32v6/alpine:latest as arm
COPY --from=build-arm /app/scan-engine /go/bin/scan-engine
COPY --from=build-arm /app/libpcap-1.9.1/ /go/bin/libpcap-1.9.1/
#COPY --from=build-arm /app/ncat /bin/ncat
#COPY --from=build-arm /app/ndiff /bin/ndiff
#COPY --from=build-arm /app/nping /bin/nping
#COPY --from=build-arm /app/nmap /bin/nmap
COPY ./scanner.sh .

ENTRYPOINT [ "./scanner.sh" ]

FROM arm64v8/alpine:latest as arm64
COPY --from=build-arm64 /app/scan-engine /go/bin/scan-engine
COPY --from=build-arm64 /app/libpcap-1.9.1/ /go/bin/libpcap-1.9.1/
#COPY --from=build-arm64 /app/ncat /bin/ncat
#COPY --from=build-arm64 /app/ndiff /bin/ndiff
#COPY --from=build-arm64 /app/nping /bin/nping
#COPY --from=build-arm64 /app/nmap /bin/nmap
COPY ./scanner.sh .
ENTRYPOINT ["./scanner.sh"]

FROM alpine:latest as amd64
COPY --from=build-amd64 /app/scan-engine /go/bin/scan-engine
COPY --from=build-amd64 /app/libpcap-1.9.1/ /go/bin/libpcap-1.9.1/
#COPY --from=build-amd64 /app/ncat /bin/ncat
#COPY --from=build-amd64 /app/ndiff /bin/ndiff
#COPY --from=build-amd64 /app/nping /bin/nping
#COPY --from=build-amd64 /app/nmap /bin/nmap
COPY ./scanner.sh .
ENTRYPOINT ["./scanner.sh"]