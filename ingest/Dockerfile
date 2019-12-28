FROM golang:latest as build

RUN apt update && apt install -y \
		gcc-arm-linux-gnueabihf \
        gcc-aarch64-linux-gnu \
		libc6-dev-armhf-cross\
        byacc flex \
        libpcap-dev
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
RUN ./build.sh