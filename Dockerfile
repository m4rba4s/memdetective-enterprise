# Multi-stage build for minimal production image
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libyara-dev \
    libncurses5-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /src
COPY . .

# Build the application
RUN make clean && make release -j$(nproc)

# Production stage - minimal runtime image
FROM ubuntu:22.04

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libyara8 \
    libncurses5 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false -d /nonexistent memory-inspector

# Copy binary and essential files
COPY --from=builder /src/memory-inspector /usr/local/bin/
COPY --from=builder /src/examples/sample_rules.yar /opt/memory-inspector/rules/
COPY --from=builder /src/examples/memory-inspector.conf /opt/memory-inspector/

# Set permissions
RUN chmod +x /usr/local/bin/memory-inspector \
    && chown root:root /usr/local/bin/memory-inspector

# Create working directory
WORKDIR /opt/memory-inspector

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD memory-inspector --version || exit 1

# Security: run as non-root when possible
# Note: For full functionality, container needs --privileged or --pid=host
USER memory-inspector

# Default command
ENTRYPOINT ["memory-inspector"]
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="Memory Inspector CLI"
LABEL org.opencontainers.image.description="Professional memory analysis tool for security research"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="Security Research Tools"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/m4rba4s/memory-inspector-cli"