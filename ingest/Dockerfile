FROM golang:latest as build-arm

RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=arm go build -installsuffix cgo -ldflags -ldflags "-w -s" -a -o ingest . && \
    file ingest

FROM golang:latest as build-arm64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=arm64 go build -installsuffix cgo -ldflags "-w -s" -a -o ingest . && \
    file ingest



FROM golang:latest as build-amd64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=amd64 go build -installsuffix cgo -ldflags "-w -s" -a -o ingest . && \
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