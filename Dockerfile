# Dockerfile for wiskess_rust - Optimized for Size

# ----------- Stage 1: Rust Builder -----------
# Compiles the Rust application
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
# Copy script needed in the intermediate stage
COPY ./tools/setup_get_git.py ./setup_get_git.py
RUN cargo clean --release
RUN cargo build --release --locked --bin ${BINARY_NAME}
# Optional: Strip the binary for further size reduction
# RUN strip "target/release/${BINARY_NAME}"


# ----------- Stage 2: Intermediate Python/Tools Builder -----------
# Installs Python dependencies and external tools, including build tools
FROM ubuntu:24.04 AS intermediate-builder

# --- Environment Vars for this stage ---
ENV VENV_PATH_INTERMEDIATE=/opt/intermediate/venv
ENV TOOL_PATH_INTERMEDIATE=/opt/intermediate/tools
ENV DOTNET_INSTALL_DIR_INTERMEDIATE="${TOOL_PATH_INTERMEDIATE}/.dotnet"

# --- Install build dependencies for this stage ---
# Only install what's needed to BUILD python extensions and download/extract tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    wget \
    curl \
    bash \
    p7zip-full \
    python3 \
    python3-pip \
    python3-venv \
    python-is-python3 \
    build-essential \
    pkg-config \
    python3-dev \
    libmagic-dev \
    libfuse3-dev \
    libicu-dev \ 
    tar \
 && rm -rf /var/lib/apt/lists/*

# --- Setup Python Virtual Env ---
RUN python3 -m venv ${VENV_PATH_INTERMEDIATE}

# --- Install Python Packages ---
RUN . ${VENV_PATH_INTERMEDIATE}/bin/activate && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        polars \
        chardet \
        datetime \
        filetype \
        requests \
        python-magic \
        colorama \
        yara-python \
        psutil \
        rfc5424-logging-handler \
        netaddr \
        libesedb-python \
        # PyQt6 \
        awscli \
        pyhindsight \
        git+https://github.com/cclgroupltd/ccl_chromium_reader.git

# --- Create and Prepare Tool Directory ---
RUN mkdir -p ${TOOL_PATH_INTERMEDIATE} && \
    mkdir -p ${TOOL_PATH_INTERMEDIATE}/Get-ZimmermanTools/net9
WORKDIR ${TOOL_PATH_INTERMEDIATE}

# --- Download/Clone/Install Tools IN THIS STAGE ---
# Git clone repositories
RUN git clone --depth 1 https://github.com/brimorlabs/KStrike KStrike && \
    git clone --depth 1 https://github.com/ANSSI-FR/bmc-tools.git bmc-tools && \
    git clone --depth 1 https://github.com/Neo23x0/loki.git loki && \
    git clone --depth 1 https://github.com/williballenthin/shellbags shellbags

# Install Loki dependencies
RUN cd ./loki && \
    ${VENV_PATH_INTERMEDIATE}/bin/python loki-upgrader.py

# Run setup_get_git.py 
# COPY --from=builder /usr/src/app/setup_get_git.py /setup_get_git.py
# RUN --mount=type=secret,id=git_token,target=/run/secrets/git_token \
#     chmod +x /setup_get_git.py && \
#     . ${VENV_PATH_INTERMEDIATE}/bin/activate && \
#     export GIT_TOKEN=$(cat /run/secrets/git_token) && \
#     python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/countercept/chainsaw" linux && \
#     python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/Yamato-Security/hayabusa" linux && \
#     python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/Velocidex/velociraptor" linux && \
#     python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/omerbenamram/evtx.git" linux && \
#     python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/omerbenamram/mft.git" linux && \
#     python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/forensicmatt/RustyUsn.git" linux && \
#     rm /setup_get_git.py

# Get Chainsaw shimcache patterns
RUN wget -nv "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -O ${TOOL_PATH_INTERMEDIATE}/shimcache_patterns.txt

# Install Vector (Installs globally, likely /usr/local/bin/vector)
RUN curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y

# Install azcopy (Download, extract binary, cleanup archive)
RUN mkdir -p ${TOOL_PATH_INTERMEDIATE}/azcopy && \
    wget -nv https://aka.ms/downloadazcopy-v10-linux -O azcopy.tar.gz && \
    tar -xvf azcopy.tar.gz --strip-components=1 -C ${TOOL_PATH_INTERMEDIATE}/azcopy && \
    # Binary is now in ${TOOL_PATH_INTERMEDIATE}/azcopy/azcopy
    rm azcopy.tar.gz

# Install .NET *Runtime* (ASP.NET Core Runtime includes base runtime)
RUN wget -nv https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh && \
    chmod +x dotnet-install.sh && \
    # Install ASP.NET Core Runtime (smaller than SDK) into specific dir
    ./dotnet-install.sh --channel 9.0 --runtime aspnetcore --install-dir ${DOTNET_INSTALL_DIR_INTERMEDIATE} --verbose && \
    # Clean up script immediately
    rm dotnet-install.sh

# Download and extract Zimmerman Tools (eztools) & Clean up archives
RUN cd ${TOOL_PATH_INTERMEDIATE}/Get-ZimmermanTools/net9 && \
    for tool in AmcacheParser AppCompatCacheParser bstrings EvtxECmd EZViewer JLECmd JumpListExplorer LECmd MFTECmd MFTExplorer PECmd RBCmd RecentFileCacheParser RECmd RegistryExplorer RLA SDBExplorer SBECmd ShellBagsExplorer SQLECmd SrumECmd SumECmd TimelineExplorer VSCMount WxTCmd; \
    do \
        echo "Downloading and extracting $tool..."; \
        wget -nv "https://download.ericzimmermanstools.com/net9/$tool.zip" -O "$tool.zip"; \
        7z x -r -aoa "$tool.zip" -o"${TOOL_PATH_INTERMEDIATE}/Get-ZimmermanTools/net9/"; \
        rm "$tool.zip"; \
    done

# --- End of Intermediate Stage ---


# ----------- Stage 3: Runtime -----------
# Creates the final, minimal image
FROM ubuntu:24.04 AS runtime

# --- Arguments ---
ARG BINARY_NAME=wiskess_rust

# --- Environment Variables for final image ---
ENV TOOL_PATH=/app/tools
ENV VENV_PATH="${TOOL_PATH}/venv"
ENV DOTNET_ROOT="${TOOL_PATH}/.dotnet"
ENV PATH="${DOTNET_ROOT}:${VENV_PATH}/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV TOOL_PATH_INTERMEDIATE=/opt/intermediate/tools
ENV VENV_PATH_INTERMEDIATE=/opt/intermediate/venv
ENV DOTNET_INSTALL_DIR_INTERMEDIATE="${TOOL_PATH_INTERMEDIATE}/.dotnet"

# --- Install Runtime Dependencies ---
# Install only libs needed to RUN the tools/app, not build them
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    # Runtime libs corresponding to -dev packages in intermediate stage
    libmagic1 \
    libicu74 \
    libesedb1 \
    libfuse3-3 \
    libesedb-utils \
    # Runtime tools kept from original list
    regripper \
    jq \
    p7zip-full \
    fd-find \
    ripgrep \
    # Base Python needed to run venv
    python3 \
    python-is-python3 \
    # Needed for running some binaries
    libc6 \
 && rm -rf /var/lib/apt/lists/*

# --- Create App User and Dirs ---
RUN groupadd --system app && \
    useradd --system --gid app --home /app --shell /sbin/nologin app && \
    mkdir -p /app/config /app/templates /app/web /app/tools && \
    chown -R app:app /app

# --- Copy Artifacts from Intermediate Stage ---
WORKDIR /app

# Copy Python virtual environment
COPY --from=intermediate-builder --chown=app:app ${VENV_PATH_INTERMEDIATE} ${VENV_PATH}

# Copy downloaded/cloned tools directory
COPY --from=intermediate-builder --chown=app:app ${TOOL_PATH_INTERMEDIATE} ${TOOL_PATH}

# Copy .NET Runtime
COPY --from=intermediate-builder --chown=app:app ${DOTNET_INSTALL_DIR_INTERMEDIATE} ${DOTNET_ROOT}

# Copy specific binaries installed elsewhere (adjust paths if needed)
# Vector likely installed to /usr/local/bin in intermediate stage
# COPY --from=intermediate-builder /usr/local/bin/vector /usr/local/bin/vectorSS
# Copy azcopy from its extracted location
COPY --from=intermediate-builder --chown=app:app ${TOOL_PATH_INTERMEDIATE}/azcopy/ ${TOOL_PATH}/azcopy/
# Ensure copied binaries are executable
# RUN chmod +x /usr/local/bin/vector
RUN chmod +x ${TOOL_PATH}/azcopy/azcopy

# Create symlinks needed at runtime
RUN ln -s ${TOOL_PATH}/azcopy/azcopy ${TOOL_PATH}/azcopy/azcopy.exe
RUN ln -s $(which 7z) /usr/local/bin/7z.exe

# --- Copy Artifacts from Rust Builder Stage ---
COPY --from=builder --chown=app:app /usr/src/app/config ./config
COPY --from=builder --chown=app:app /usr/src/app/templates ./templates
COPY --from=builder --chown=app:app /usr/src/app/web ./web
COPY --from=builder --chown=app:app /usr/src/app/tools ./tools

# Run setup_get_git.py 
WORKDIR /app/tools
COPY --from=builder /usr/src/app/setup_get_git.py /setup_get_git.py
RUN --mount=type=secret,id=git_token,target=/run/secrets/git_token \
    chmod +x /setup_get_git.py && \
    . ${VENV_PATH}/bin/activate && \
    export GIT_TOKEN=$(cat /run/secrets/git_token) && \
    python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/countercept/chainsaw" linux && \
    python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/Yamato-Security/hayabusa" linux && \
    python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/Velocidex/velociraptor" linux && \
    python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/omerbenamram/evtx.git" linux && \
    python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/omerbenamram/mft.git" linux && \
    python /setup_get_git.py "${GIT_TOKEN}" "https://github.com/forensicmatt/RustyUsn.git" linux && \
    rm /setup_get_git.py

# Copy the compiled Rust binary
COPY --from=builder /usr/src/app/target/release/${BINARY_NAME} /usr/local/bin/${BINARY_NAME}
RUN chmod +x /usr/local/bin/${BINARY_NAME}

# --- Final Configuration ---
# Ensure all of /app is owned by app user (redundant with mkdir but safe)
RUN chown -R app:app /app/tools

# Expose the GUI port
EXPOSE 8080

# Switch to the non-root user
USER app

# Set final working directory
WORKDIR /app

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/wiskess_rust", "--tool-path", "/app/tools"]
# CMD ["--help"]