# Semgrep CE 1.183.0 (official Docker Hub image) + semgrep/semgrep-rules at commit 16b9e6d4
FROM semgrep/semgrep@sha256:2e45517a85e13a9cca14a2a00df6bb48affd66b8ebfae1b0991cd57578362fb0
USER root
RUN apk add --no-cache git >/dev/null 2>&1 || true;     git clone -q https://github.com/semgrep/semgrep-rules /rules-all && cd /rules-all && git checkout -q 16b9e6d45f10649f6a531ec4838ed9924372c3bc
USER 65534:65534
ENV HOME=/tmp
ENTRYPOINT ["semgrep"]
# Rule selection (fixed before the first scan): every rule file under a directory of semgrep-rules whose path contains
# "crypt" (case-insensitive), test fixtures excluded. Copied to /rules; the scan uses --config /rules only.
USER root
RUN cd /rules-all && mkdir /rules && find . -path ./.git -prune -o -type d -ipath '*crypt*' -print | while read d; do \
      find "$d" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) ! -name '*.test.*' | while read f; do mkdir -p "/rules/$(dirname "$f")" && cp "$f" "/rules/$f"; done; done \
 && find /rules -type f | sort > /tmp/INDEX.txt && mv /tmp/INDEX.txt /rules/INDEX.txt \
 && echo "semgrep-rules@$(git -C /rules-all rev-parse HEAD) $(wc -l < /rules/INDEX.txt) rule files" > /rules/VERSION && wc -l < /rules/INDEX.txt
USER 65534:65534
