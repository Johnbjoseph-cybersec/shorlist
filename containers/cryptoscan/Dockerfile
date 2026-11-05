# CSNP CryptoScan v1.5.0 (tag object 60f51b67…), official: go install from github.com/csnp/cryptoscan
FROM golang@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/csnp/cryptoscan/cmd/cryptoscan@v1.5.0
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY --from=build /out/cryptoscan /usr/local/bin/cryptoscan
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/cryptoscan"]
