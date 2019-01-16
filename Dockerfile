FROM ruby:latest
MAINTAINER Cag

# This is to be able to talk to Tenable API
ARG TENABLEIO_ACCESS_KEY
ARG TENABLEIO_SECRET_KEY

ENV TENABLEIO_ACCESS_KEY "$TENABLEIO_ACCESS_KEY"
ENV TENABLEIO_SECRET_KEY "$TENABLEIO_SECRET_KEY"

# Make a landing location for results
RUN mkdir -p /app/results && \
    mkdir -p /app/vendor && \
    mkdir -p /app/vautomator

# Update deps and install make utils for compiling tools
# and clean up in the end in the same layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends unzip \
    dos2unix build-essential make curl \
    nmap software-properties-common && \
    apt-get install -y python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN cd /app/vendor && \ 
    wget -nv https://bootstrap.pypa.io/get-pip.py && \
    python2 get-pip.py

# Install and compile dirb
COPY ./vendor/dirb222.tar.gz /app/vendor/dirb222.tar.gz
RUN tar -xvf /app/vendor/dirb222.tar.gz -C /app/vendor/ && \
    chmod -R 777 /app/vendor/dirb222 && \
    chown -R root /app/vendor/dirb222 && \
    cd /app/vendor/dirb222/ && ./configure && \
    make
COPY ./vendor/gobuster-master.zip /app/vendor/gobuster-master.zip
RUN unzip /app/vendor/gobuster-master.zip -d /app/vendor/ && \
    chmod -R 777 /app/vendor/gobuster-master && \
    chown -R root /app/vendor/gobuster-master

# Install ssh_scan
RUN gem install ssh_scan

# Install HTTP Observatory tool
RUN curl -sL https://deb.nodesource.com/setup_11.x | bash -
RUN apt-get install -y nodejs && \
    npm install -g observatory-cli

# Install TLS Observatory tool
# First build Go from master
# TODO: Change hard-coded Go version
RUN cd /tmp && \
    wget -nv https://dl.google.com/go/go1.11.2.linux-amd64.tar.gz && \
    tar -C /app/vendor/ -xzf /tmp/go1.11.2.linux-amd64.tar.gz

ENV GOPATH /app/vendor/go/bin
ENV PATH $GOPATH:$PATH
ENV PATH $GOPATH/bin:$PATH

RUN go get github.com/mozilla/tls-observatory/tlsobs
RUN wget -nv http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip && \
    wget -nv http://s3.amazonaws.com/alexa-static/top-1m.csv.zip -O alexa-top-1m.csv.zip && \
    mkdir -p /etc/tls-observatory && \
    unzip top-1m.csv.zip && \
    mv top-1m.csv /etc/tls-observatory/cisco-top-1m.csv && \
    unzip alexa-top-1m.csv.zip && \
    mv top-1m.csv /etc/tls-observatory/alexa-top-1m.csv && \
    rm top-1m.csv.zip && rm alexa-top-1m.csv.zip && \
    dos2unix /etc/tls-observatory/cisco-top-1m.csv && dos2unix /etc/tls-observatory/alexa-top-1m.csv

COPY . /app/vautomator
RUN pip3 install -r /app/vautomator/requirements.txt && \
    chmod +x /app/vautomator/run.py
WORKDIR /app/vautomator
