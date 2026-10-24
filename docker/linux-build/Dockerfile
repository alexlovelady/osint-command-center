# Linux build + verification environment (Ubuntu 22.04: glibc 2.35, so the produced binaries run on 22.04 and newer).
# Everything downloaded here is pinned or hash-checked: uv by SHA-256, Rust through rustup's own signature/hash checks.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential pkg-config libssl-dev libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
      libayatana-appindicator3-dev libxdo-dev patchelf xvfb xauth x11-utils imagemagick xdotool perl file git procps tcpdump \
    && rm -rf /var/lib/apt/lists/*
ARG UV_VERSION=0.13.5
ARG UV_SHA256=f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f
RUN curl -fsSL -o /tmp/uv.tgz "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz" \
 && echo "${UV_SHA256}  /tmp/uv.tgz" | sha256sum -c - \
 && tar -xzf /tmp/uv.tgz --strip-components=1 -C /usr/local/bin && rm /tmp/uv.tgz
# Node.js (pinned, SHA-256 checked) + pnpm (pinned): the desktop shell embeds the built React UI, so the UI must be built in this container.
ARG NODE_VERSION=24.16.0
ARG NODE_SHA256=d804845d34eddc21dc1092b519d643ef40b1f58ec5dec5c22b1f4bd8fabde6c9
ARG PNPM_VERSION=11.18.0
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils && rm -rf /var/lib/apt/lists/*  && curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"  && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c -  && tar -xJf /tmp/node.tar.xz --strip-components=1 -C /usr/local && rm /tmp/node.tar.xz  && npm install -g "pnpm@${PNPM_VERSION}" --no-fund --no-audit  && node --version && pnpm --version
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
WORKDIR /work
