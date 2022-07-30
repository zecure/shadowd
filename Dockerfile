FROM ubuntu:20.04 AS builder
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential \
       cmake \
       g++ \
       libssl-dev \
       libboost-test-dev \
       libboost-system-dev \
       libboost-thread-dev \
       libboost-program-options-dev \
       libboost-regex-dev \
       libasio-dev \
       libcrypto++-dev \
       libdbi-dev && \
   rm -rf /var/lib/apt/lists/*
COPY . /shadowd
RUN mkdir /shadowd/build
WORKDIR /shadowd/build
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release .. && \
    make shadowd


FROM ubuntu:20.04
MAINTAINER Hendrik Buchwald
ENV SHADOWD_ADDRESS 0.0.0.0
EXPOSE 9115
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libboost-program-options1.71.0 \
        libboost-regex1.71.0 \
        libboost-system1.71.0 \
        libboost-thread1.71.0 \
        libcrypto++6 \
        libdbi1 \
        libdbd-pgsql \
        libdbd-mysql \
        libssl1.1 && \
    rm -rf /var/lib/apt/lists/*
RUN addgroup \
        --quiet \
        --system \
        shadowd && \
    adduser \
        --quiet \
    	--system \
    	--ingroup shadowd \
    	--no-create-home \
    	--home /dev/null \
    	--disabled-password \
    	--disabled-login \
    	shadowd && \
    mkdir /etc/shadowd && \
    touch /etc/shadowd/shadowd.ini && \
    chown root:shadowd /etc/shadowd/shadowd.ini && \
    chmod 640 /etc/shadowd/shadowd.ini
COPY --from=builder /shadowd/misc/docker/docker-entrypoint.sh /
COPY --from=builder /shadowd/build/src/shadowd /usr/bin/shadowd
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/bin/shadowd", "-c", "/etc/shadowd/shadowd.ini", "-U", "shadowd", "-G", "shadowd", "-W"]
