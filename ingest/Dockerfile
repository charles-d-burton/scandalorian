FROM golang:alpine as build

RUN apk add --update --no-cache ca-certificates git gcc libc-dev libpcap-dev
RUN mkdir /app
RUN uname -a
WORKDIR /app
COPY ./ .