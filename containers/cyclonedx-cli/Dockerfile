# cyclonedx-cli 0.33.1 (2026-07-23, Apache-2.0), the self-contained linux-x64 release binary from
# github.com/CycloneDX/cyclonedx-cli, checked against the sha256 GitHub lists for the asset.
# Runs offline (--network none); invariant globalization, so no ICU is needed.
FROM debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ADD --checksum=sha256:bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746 \
    https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.33.1/cyclonedx-linux-x64 /usr/local/bin/cyclonedx
RUN chmod 755 /usr/local/bin/cyclonedx
USER 65534:65534
ENV HOME=/tmp DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
ENTRYPOINT ["/usr/local/bin/cyclonedx"]
