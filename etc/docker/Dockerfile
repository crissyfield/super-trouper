FROM alpine:3.22

# GoReleaser arranges release binaries by their Buildx target platform
ARG TARGETPLATFORM

# Create an unprivileged account for the service
RUN adduser -D -S -u 65532 super-trouper

# Install the release binary at a standard executable path
COPY ${TARGETPLATFORM}/super-trouper /usr/local/bin/super-trouper

# Run the service without root privileges
USER super-trouper

# Always execute the release binary
ENTRYPOINT ["/usr/local/bin/super-trouper"]
