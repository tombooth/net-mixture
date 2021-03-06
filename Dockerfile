FROM ubuntu:bionic

RUN apt-get update && apt-get install -y gnupg ca-certificates

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD && \
    echo "deb https://repo.iovisor.org/apt/bionic bionic main" | tee /etc/apt/sources.list.d/iovisor.list && \
    apt-get update && \
    apt-get install -y bcc-tools libbcc-examples bcc golang

ENV GOPATH=/go

RUN mkdir -p /go/src/github.com/tombooth
COPY . /go/src/github.com/tombooth/net-mixture

RUN go build -o /net-mixture github.com/tombooth/net-mixture


ENTRYPOINT ["/net-mixture"]
