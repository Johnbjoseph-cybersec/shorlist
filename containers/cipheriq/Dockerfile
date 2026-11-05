# CipherIQ cbom-generator: release v1.9.4 asset cbom-generator-1.9.3-linux-amd64.tar.gz (the v1.9.4 release ships this file),
# sha256 from the release's checksums.txt. Install per README "Quick Install from Release".
FROM ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update -qq && apt-get install -y -qq curl ca-certificates libssl3t64 libjson-c5 libyaml-0-2 libjansson4 libcurl4t64 libncursesw6 libncurses6 >/dev/null \
 && cd /tmp && curl -sSLO https://github.com/CipherIQ/cbom-generator/releases/download/v1.9.4/cbom-generator-1.9.3-linux-amd64.tar.gz \
 && echo "2b94874c8486260c719b0777cf5774751f46155c4e075c1125eb3aef17576613  cbom-generator-1.9.3-linux-amd64.tar.gz" | sha256sum -c - \
 && mkdir x && tar -xzf cbom-generator-1.9.3-linux-amd64.tar.gz -C x && ls -R x | head -20 \
 && install -m 755 $(find x -name 'cbom-generator-1.9.3-linux-amd64' -type f) /usr/local/bin/cbom-generator \
 && mkdir -p /usr/local/share/cbom-generator && cp -r $(find x -maxdepth 2 -name plugins -type d) $(find x -maxdepth 2 -name registry -type d) /usr/local/share/cbom-generator/ \
 && rm -rf /tmp/x /tmp/*.tar.gz && apt-get purge -y -qq curl >/dev/null && rm -rf /var/lib/apt/lists/*
USER 65534:65534
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/cbom-generator"]
