# Dockerfile for wiskess_rust

# ----------- Stage 1: Builder -----------
FROM rust:1.83-slim-bookworm AS builder
WORKDIR /usr/src/app
ARG BINARY_NAME=wiskess_rust
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {println!(\"Dummy main for dependency caching\");}" > src/main.rs
RUN cargo build --release --locked
RUN rm -rf src
COPY ./src ./src
COPY ./templates ./templates
COPY ./web ./web
COPY ./config ./config
COPY ./tools ./tools
COPY ./tools/setup_get_git.py ./setup_get_git.py
RUN cargo clean --release
RUN cargo build --release --locked --bin ${BINARY_NAME}
# Optional: Strip
# RUN strip "target/release/${BINARY_NAME}"


# ----------- Stage 2: Runtime -----------
FROM debian:bookworm-slim

# --- Build Arguments ---
ARG BINARY_NAME=wiskess_rust
ARG GITHUB_TOKEN # Pass with --build-arg or use secrets

# --- Environment Variables ---
ENV TOOL_PATH=/app/tools
ENV VENV_PATH="${TOOL_PATH}/venv"
ENV DOTNET_ROOT="${TOOL_PATH}/.dotnet"
ENV PATH="${DOTNET_ROOT}:${PATH}"

# --- Install System Dependencies (APT) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    wget \
    curl \
    bash \
    p7zip-full \
    fd-find \
    ripgrep \
    regripper \
    python3-pip \
    python3-venv \
    python-is-python3 \
    libesedb-utils \
    libesedb-dev \
    libmagic1 \
    libmagic-dev \
    jq \
    tar \
    build-essential \
    pkg-config \
    # --- ADDED FOR dotnet Globalization ---
    libicu-dev \
 && rm -rf /var/lib/apt/lists/*

# --- Setup Python Virtual Environment (Python 3) ---
RUN python3 -m venv ${VENV_PATH}

# --- Install Python Packages (pip for Python 3) ---
RUN . ${VENV_PATH}/bin/activate && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        polars \
        chardet \
        datetime \
        filetype \
        requests \
        # libesedb-python \
        python-magic \
        colorama \
        yara-python \
        psutil \
        rfc5424-logging-handler \
        netaddr \
        PyQt6 \
        awscli \
        pyhindsight \
        git+https://github.com/cclgroupltd/ccl_chromium_reader.git

# --- Create Tool Directory ---
RUN mkdir -p ${TOOL_PATH} && \
    mkdir -p ${TOOL_PATH}/Get-ZimmermanTools/net9

# --- Download/Clone Tools ---
WORKDIR ${TOOL_PATH} 

# Git clone repositories
RUN git clone --depth 1 https://github.com/brimorlabs/KStrike KStrike && \
    git clone --depth 1 https://github.com/ANSSI-FR/bmc-tools.git bmc-tools && \
    git clone --depth 1 https://github.com/Neo23x0/loki.git loki && \
    git clone --depth 1 https://github.com/williballenthin/shellbags shellbags

# Run setup_get_git.py AFTER clones
COPY --from=builder /usr/src/app/setup_get_git.py /setup_get_git.py
RUN chmod +x /setup_get_git.py && \
    . ${VENV_PATH}/bin/activate && \
    python /setup_get_git.py "${GITHUB_TOKEN}" "https://github.com/countercept/chainsaw" linux && \
    python /setup_get_git.py "${GITHUB_TOKEN}" "https://github.com/Yamato-Security/hayabusa" linux && \
    python /setup_get_git.py "${GITHUB_TOKEN}" "https://github.com/Velocidex/velociraptor" linux && \
    python /setup_get_git.py "${GITHUB_TOKEN}" "https://github.com/omerbenamram/evtx.git" linux && \
    python /setup_get_git.py "${GITHUB_TOKEN}" "https://github.com/omerbenamram/mft.git" linux && \
    python /setup_get_git.py "${GITHUB_TOKEN}" "https://github.com/forensicmatt/RustyUsn.git" linux && \
    rm /setup_get_git.py

# Install Loki dependencies
RUN cd ./loki && \
    ${VENV_PATH}/bin/python loki-upgrader.py

# Get Chainsaw shimcache patterns
RUN wget -nv "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -O ${TOOL_PATH}/shimcache_patterns.txt

# Install Vector
RUN curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y

# Install azcopy & create symlinks
RUN wget -nv https://aka.ms/downloadazcopy-v10-linux -O azcopy.tar.gz && \
    mkdir -p ${TOOL_PATH}/azcopy && \
    tar -xvf azcopy.tar.gz --strip-components=1 -C ${TOOL_PATH}/azcopy && \
    ln -s ${TOOL_PATH}/azcopy/azcopy /usr/local/bin/azcopy && \
    ln -s ${TOOL_PATH}/azcopy/azcopy ${TOOL_PATH}/azcopy/azcopy.exe && \
    rm azcopy.tar.gz

# Install .NET 9 SDK
RUN wget -nv https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh && \
    chmod +x dotnet-install.sh && \
    ./dotnet-install.sh --channel 9.0 --install-dir ${DOTNET_ROOT} --verbose && \
    rm dotnet-install.sh

# Download and extract Zimmerman Tools (eztools)
RUN cd ${TOOL_PATH}/Get-ZimmermanTools/net9 && \
    for tool in AmcacheParser AppCompatCacheParser bstrings EvtxECmd EZViewer JLECmd JumpListExplorer LECmd MFTECmd MFTExplorer PECmd RBCmd RecentFileCacheParser RECmd RegistryExplorer RLA SDBExplorer SBECmd ShellBagsExplorer SQLECmd SrumECmd SumECmd TimelineExplorer VSCMount WxTCmd; do \
        echo "Downloading $tool..."; \
        wget -nv "https://download.ericzimmermanstools.com/net9/$tool.zip" -O "$tool.zip"; \
        echo "Extracting $tool..."; \
        7z x -r -aoa "$tool.zip" -o"${TOOL_PATH}/Get-ZimmermanTools/net9/"; \
        rm "$tool.zip"; \
    done

# Create symlink for 7z.exe compatibility
RUN ln -s $(which 7z) /usr/local/bin/7z.exe

# --- Final Setup ---
# Set back to the main application working directory
WORKDIR /app 

# Create non-root user (AFTER installs requiring root)
RUN groupadd --system app && \
    useradd --system --gid app --home /app --shell /sbin/nologin app

# --- Runtime assets ---
COPY --from=builder --chown=app:app /usr/src/app/config ./config
COPY --from=builder --chown=app:app /usr/src/app/templates ./templates
COPY --from=builder --chown=app:app /usr/src/app/web ./web
COPY --from=builder --chown=app:app /usr/src/app/tools ./tools

# Copy the compiled binary
COPY --from=builder /usr/src/app/target/release/${BINARY_NAME} /usr/local/bin/${BINARY_NAME}
RUN chmod +x /usr/local/bin/${BINARY_NAME}

RUN chown -R app:app /app

# Expose the GUI port
EXPOSE 8080

# Switch to the non-root user
USER app

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/wiskess_rust", "--tool-path", "/app/tools"]
# CMD ["--help"]