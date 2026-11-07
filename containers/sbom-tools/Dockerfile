# sbom-tools 0.3.0 (2026-10-12, MIT), the release binary from github.com/sbom-tool/sbom-tools,
# checked against the sha256 GitHub lists for the asset. Runs offline (--network none).
# Runtime base: debian trixie-slim (glibc 2.41); the binary needs glibc >= 2.39, bookworm has 2.36.
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS fetch
ADD --checksum=sha256:3817fbc006aca0eabe7878d51f80204802b2964d097a22d49d5538bfffed7b24 \
    https://github.com/sbom-tool/sbom-tools/releases/download/v0.3.0/sbom-tools-linux-x86_64.tar.gz /sbom-tools.tar.gz
RUN mkdir /out && tar -xzf /sbom-tools.tar.gz -C /out && find /out -type f -name sbom-tools -exec cp {} /sbom-tools \; \
 && chmod 755 /sbom-tools
FROM debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=fetch /sbom-tools /usr/local/bin/sbom-tools
USER 65534:65534
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/sbom-tools"]
