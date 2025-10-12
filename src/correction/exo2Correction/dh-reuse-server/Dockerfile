FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    ca-certificates \
    openssl \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Show versions
RUN openssl version

WORKDIR /app

# Server source
COPY server.c /app/server.c
RUN gcc -O2 -Wall -Wextra -o /app/tls_vuln_server /app/server.c -lssl -lcrypto

# Certificates directory
RUN mkdir -p /app/certs

# Entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 443
CMD ["/app/entrypoint.sh"]
