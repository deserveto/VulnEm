# ---------------------------------------------------------------------------
# VulnEm agent sandbox — Debian + pentest tooling, non-root user.
# Everything the agent executes runs inside this container, never on the host.
# ---------------------------------------------------------------------------

# Builder stage: compile Go tools here so the Go toolchain never reaches the
# runtime image (saves ~1GB). Floating `golang:bookworm` because projectdiscovery
# tools regularly require the newest Go toolchain. Each tool gets its own RUN
# layer (a failed build resumes from the last success) and GOMAXPROCS is capped
# so parallel compilation cannot OOM the Docker VM.
FROM golang:bookworm AS builder

ENV GOBIN=/out/bin GOMAXPROCS=2
RUN mkdir -p /out/bin
RUN go install -v github.com/ffuf/ffuf/v2@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget unzip git \
      jq ripgrep file xxd less procps net-tools iputils-ping \
      dnsutils netcat-traditional \
      nmap sqlmap whatweb \
      perl \
      python3 python3-pip \
      sudo vim-tiny && \
    rm -rf /var/lib/apt/lists/*

# nikto is not in Debian repos (Kali-only); upstream is a plain Perl script.
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Python libs agents commonly need for PoCs (stdlib-only also works).
RUN pip3 install --break-system-packages --no-cache-dir requests

# Phase 4 white-box: semgrep + a vendored ruleset, so source analysis works
# with NO internet (the registry is unreachable on internal lab networks).
# Rules are validated at build time — a broken rule file fails the build.
COPY semgrep-rules/ /opt/semgrep-rules/
RUN pip3 install --break-system-packages --no-cache-dir semgrep && \
    semgrep --validate --config /opt/semgrep-rules && \
    mv /usr/local/bin/semgrep /usr/local/bin/semgrep.real && \
    printf '#!/bin/sh\nexec semgrep.real "$@" --metrics=off --disable-version-check\n' \
      > /usr/local/bin/semgrep && chmod 0755 /usr/local/bin/semgrep
# ^ SEMGREP_SEND_METRICS=off (bottom of file) only kills telemetry; semgrep
# still CONNECTs semgrep.dev for a version check on every run, which the
# scope proxy blocks (noise + retries). The wrapper silences both for every
# invocation, whatever flags the agent passes.

# Headless Chromium via Playwright, baked in at build time so browser tooling
# works with NO internet access (lab networks are internal). Browsers go to a
# system-wide path so the non-root pentester user finds them. The browser runs
# with --no-sandbox (container isolation is the security boundary).
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN pip3 install --break-system-packages --no-cache-dir playwright && \
    python3 -m playwright install --with-deps chromium

COPY --from=builder /out/bin/ /usr/local/bin/

# ProjectDiscovery tools (httpx/subfinder/katana/nuclei) phone api.pdtm.sh for
# a version check on EVERY run; the scope proxy blocks those CONNECTs (by
# design) and the blocked retries burn agent turns and flood the blocked-event
# log. There is no env switch — only the -disable-update-check flag — so ship
# wrappers that always pass it (real binaries live beside them as *.real).
# katana's -headless mode would also download its own Chromium at runtime
# (blocked by the scope proxy); it gets the baked Playwright Chromium instead,
# via a stable symlink that hides the versioned directory.
RUN ln -s /opt/ms-playwright/chromium-*/chrome-linux64/chrome /usr/local/bin/headless-chrome && \
    for t in httpx subfinder katana nuclei; do \
      mv "/usr/local/bin/$t" "/usr/local/bin/$t.real" && \
      printf '#!/bin/sh\nexec %s.real "$@" -disable-update-check\n' "$t" \
        > "/usr/local/bin/$t" && \
      chmod 0755 "/usr/local/bin/$t"; \
    done && \
    printf '#!/bin/sh\nfor a in "$@"; do case "$a" in -hl|-headless|-hh|-hybrid) \
exec katana.real "$@" -disable-update-check -scp /usr/local/bin/headless-chrome -nos;; esac; done\n\
exec katana.real "$@" -disable-update-check\n' \
      > /usr/local/bin/katana && chmod 0755 /usr/local/bin/katana

# Non-root operator with passwordless sudo (some tools insist on it).
RUN useradd -m -s /bin/bash pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/pentester && \
    chmod 0440 /etc/sudoers.d/pentester && \
    mkdir -p /home/pentester/workspace /usr/share/wordlists && \
    chown -R pentester:pentester /home/pentester/workspace

# Bake nuclei templates so the sandbox works with no internet access (the
# runtime scope proxy blocks the template download). nuclei.real, NOT the
# shim: the shim's appended -disable-update-check makes -update-templates
# a silent no-op.
RUN su - pentester -c 'nuclei.real -update-templates' || true

# Common content-discovery wordlists for ffuf (build-time download, baked in).
RUN curl -sfL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
      -o /usr/share/wordlists/common.txt || true && \
    curl -sfL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt \
      -o /usr/share/wordlists/raft-medium-directories.txt || true

# Semgrep phones home to semgrep.dev for metrics even with vendored local
# rules; the scope proxy blocks those CONNECTs (by design) and the retries
# burn agent turns. Declared last so heavy cached layers above survive rebuilds.
ENV SEMGREP_SEND_METRICS=off

USER pentester
WORKDIR /home/pentester/workspace

# Kept alive by the runner via `sleep infinity`; agent drives it with exec.
CMD ["sleep", "infinity"]
