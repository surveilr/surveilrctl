FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  build-essential \
  curl \
  pkg-config \
  libssl-dev \
  git \
  ca-certificates \
  wget \
  && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /opt
RUN wget https://www.openssl.org/source/openssl-1.1.1q.tar.gz && \
    tar -xzf openssl-1.1.1q.tar.gz && \
    cd openssl-1.1.1q && \
    ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib && \
    make -j$(nproc) && \
    make install

ENV OPENSSL_LIB_DIR=/usr/local/ssl/lib
ENV OPENSSL_INCLUDE_DIR=/usr/local/ssl/include
ENV OPENSSL_STATIC=1

WORKDIR /app