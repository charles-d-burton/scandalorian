FROM golang:latest as build-arm

RUN apt update && apt install -y \
		gcc-arm* \
		libc6-dev-armhf-cross\
        byacc flex \
        libpcap-dev \
        file
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
    CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags '"-L./libpcap-$PCAPV" -w -extldflags "-static"' -installsuffix cgo -a -o ingest . && \
    file ingest

#CGO_LDFLAGS="-L./libpcap-$PCAPV -s -w"

FROM golang:latest as build-arm64
RUN apt update && apt install -y \
        gcc-aarch64* \
        libc6-dev-arm64-cross\
        byacc flex \
        libpcap-dev \
        file
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
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '"-L./libpcap-$PCAPV" -w -extldflags "-static"' -installsuffix cgo -a -o ingest . && \
    file ingest



FROM golang:latest as build-amd64
RUN apt update && apt install -y \
        build-essential \
        byacc flex \
        libpcap-dev \
        file
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
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '"-L./libpcap-$PCAPV" -w -extldflags "-static"' -installsuffix cgo -a -o ingest . && \
    file ingest



FROM scratch as arm
COPY --from=build-arm /app/ingest /go/bin/ingest
COPY --from=build-arm /app/libpcap-1.9.1/ /go/bin/libpcap-1.9.1/
ENTRYPOINT [ "/go/bin/ingest" ]

FROM scratch as arm64
COPY --from=build-arm64 /app/ingest /go/bin/ingest
COPY --from=build-arm64 /app/libpcap-1.9.1/ /go/bin/libpcap-1.9.1/
ENTRYPOINT ["/go/bin/ingest"]

FROM scratch as amd64
COPY --from=build-amd64 /app/ingest /go/bin/ingest
COPY --from=build-amd64 /app/libpcap-1.9.1/ /go/bin/libpcap-1.9.1/
ENTRYPOINT ["/go/bin/ingest"]