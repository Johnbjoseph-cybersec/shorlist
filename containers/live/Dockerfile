# ShorList live harness: one image for the OpenSSH server, `openssl s_server`, and the
# reference client (openssl s_client, ssh -vv, a raw ClientHello in python3, tcpdump) used for the wire check and the pcap.
# Base pinned by digest; Alpine package versions are not pinnable by digest and are printed
# into /versions.txt at build time (the harness records that file in every result).
FROM alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache openssl openssh-server openssh-client tcpdump python3 >/dev/null \
 && ssh-keygen -A >/dev/null \
 && mkdir -p /certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=srv -days 3650 -keyout /certs/rsa.key -out /certs/rsa.pem 2>/dev/null \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=srv -days 3650 -keyout /certs/ecdsa.key -out /certs/ecdsa.pem 2>/dev/null \
 && chmod 644 /certs/* \
 && { cat /etc/alpine-release; apk info -v 2>/dev/null | grep -E '^(openssl|openssh|tcpdump|libssl3|python3)'; ssh -V 2>&1; openssl version; } > /versions.txt
