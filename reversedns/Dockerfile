FROM golang:latest as build-arm

RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=arm go build -a -installsuffix cgo -ldflags="-w -s" -o reversedns

FROM golang:latest as build-arm64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=arm64 go build -a -installsuffix cgo -ldflags="-w -s" -o reversedns

FROM golang:latest as build-amd64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o reversedns



FROM scratch as arm
COPY --from=build-arm /app/reversedns /go/bin/reversedns
ENTRYPOINT [ "/go/bin/reversedns" ]

FROM scratch as arm64
COPY --from=build-arm64 /app/reversedns /go/bin/reversedns
ENTRYPOINT ["/go/bin/reversedns"]

FROM scratch as amd64
COPY --from=build-amd64 /app/reversedns /go/bin/reversedns
ENTRYPOINT ["/go/bin/reversedns"]