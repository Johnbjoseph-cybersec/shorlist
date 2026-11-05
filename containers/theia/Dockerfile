# cbomkit-theia v1.1.2 (commit dcd95ac8…), official: go install from github.com/cbomkit/cbomkit-theia
# (upstream Dockerfile not used: it turns off TLS and checksum verification for apk/git/go)
FROM golang@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/cbomkit/cbomkit-theia@v1.1.2 \
 && go version -m /out/cbomkit-theia | awk '$1=="mod"{print "cbomkit-theia " $3}' > /out/VERSION
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY --from=build /out/cbomkit-theia /usr/local/bin/cbomkit-theia
COPY --from=build /out/VERSION /VERSION
USER 65534:65534
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/cbomkit-theia"]
