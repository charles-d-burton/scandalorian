FROM golang:latest as build-arm

RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
RUN GOOS=linux GOARCH=arm go build -a -installsuffix cgo -ldflags="-w -s" -o scan-engine .

FROM golang:latest as build-arm64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
RUN GOOS=linux GOARCH=arm64 go build -a -installsuffix cgo -ldflags="-w -s" -o scan-engine .

FROM golang:latest as build-amd64
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
RUN GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o scan-engine .



FROM arm32v6/alpine:latest as arm
COPY --from=build-arm /app/scan-engine /go/bin/scan-engine
COPY ./scanner.sh .
COPY ./args.txt /go/bin/args.txt
ENTRYPOINT [ "./scanner.sh" ]

FROM arm64v8/alpine:latest as arm64
COPY --from=build-arm64 /app/scan-engine /go/bin/scan-engine
#COPY --from=build-arm64 /app/ncat /bin/ncat
#COPY --from=build-arm64 /app/ndiff /bin/ndiff
#COPY --from=build-arm64 /app/nping /bin/nping
#COPY --from=build-arm64 /app/nmap /bin/nmap
COPY ./scanner.sh .
COPY ./args.txt /go/bin/args.txt
ENTRYPOINT ["./scanner.sh"]

FROM alpine:latest as amd64
COPY --from=build-amd64 /app/scan-engine /go/bin/scan-engine
#COPY --from=build-amd64 /app/ncat /bin/ncat
#COPY --from=build-amd64 /app/ndiff /bin/ndiff
#COPY --from=build-amd64 /app/nping /bin/nping
#COPY --from=build-amd64 /app/nmap /bin/nmap
COPY ./scanner.sh .
COPY ./args.txt /go/bin/args.txt
ENTRYPOINT ["./scanner.sh"]