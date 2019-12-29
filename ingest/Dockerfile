FROM golang:latest as build-arm

RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=arm go build -a -installsuffix cgo -ldflags="-w -s" -o ingest

FROM golang:latest as build-arm64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=arm64 go build -a -installsuffix cgo -ldflags="-w -s" -o ingest

FROM golang:latest as build-amd64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o ingest



FROM scratch as arm
COPY --from=build-arm /app/ingest /go/bin/ingest
ENTRYPOINT [ "/go/bin/ingest" ]

FROM scratch as arm64
COPY --from=build-arm64 /app/ingest /go/bin/ingest
ENTRYPOINT ["/go/bin/ingest"]

FROM scratch as amd64
COPY --from=build-amd64 /app/ingest /go/bin/ingest
ENTRYPOINT ["/go/bin/ingest"]