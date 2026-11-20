FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip git clang curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages semgrep==1.185.0

ARG TARGETARCH
RUN if [ "$TARGETARCH" = arm64 ]; then p=linux-arm64; else p=linux64; fi \
    && curl -fsSL -o /tmp/codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/v2.27.4/codeql-$p.zip \
    && unzip -q /tmp/codeql.zip -d /opt && rm /tmp/codeql.zip

# shared home so packs are found no matter which uid runs the container
# codeql db goes in a docker volume at /codeql, it hangs on a mounted host folder
ENV PATH=/opt/codeql:$PATH HOME=/home/llmfuzz LLMFUZZ_CONTAINER=1
COPY static_analysis/codeql/qlpack.yml static_analysis/codeql/codeql-pack.lock.yml /tmp/qlpack/
RUN mkdir -p $HOME \
    && codeql pack download codeql/cpp-queries codeql/cpp-all \
    && cd /tmp/qlpack && codeql pack install \
    && chmod -R a+rwX $HOME \
    && mkdir -m 777 /codeql \
    && git config --system safe.directory '*'

WORKDIR /llmfuzz
