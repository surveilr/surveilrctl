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
RUN wget https://www.openssl.org/source/openssl-1.1.1.tar.gz && \
    tar -xvzf openssl-1.1.1.tar.gz && \
    cd openssl-1.1.1 && \
    ./config no-shared --prefix=/usr/local/openssl --openssldir=/usr/local/openssl && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf openssl-1.1.1.tar.gz openssl-1.1.1

ENV OPENSSL_STATIC=true
ENV OPENSSL_DIR=/usr/local/openssl
ENV PKG_CONFIG_PATH=/usr/local/openssl/lib/pkgconfig
ENV PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:/usr/local/lib/pkgconfig"

WORKDIR /app