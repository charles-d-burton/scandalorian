FROM golang:latest as build

RUN apt update && apt install -y \
		gcc-arm* \
        gcc-aarch64* \
		libc6-dev-armhf-cross\
        libc6-dev-arm64-cross\
        byacc flex \
        libpcap-dev \
        file
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN ls -al
RUN ./build.sh

FROM scratch as arm
COPY --from=ingest:base ingest-arm ingest
ENTRYPOINT [ "ingest" ]

FROM scratch as arm64
COPY --from=ingest:base ingest-arm64 ingest
ENTRYPOINT ["ingest"]

FROM scratch as amd64
COPY --from=ingest:base ingest-amd64 ingest
ENTRYPOINT ["ingest"]