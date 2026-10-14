# caparra-gate (and the bnap-signer it talks to), multi-stage.
#
#   docker build -t caparra-gate .
#   docker run --rm -p 8080:8080 -v /etc/caparra:/etc/caparra:ro \
#     -v caparra-data:/var/lib/caparra caparra-gate run --config /etc/caparra/gate.toml
#
# The runtime image is distroless (glibc, no shell) and runs as the
# non-root user 65532. Run bnap-signer as its own user in its own container
# or on the host, and share only its socket directory with the gate.

# Override with --build-arg RUST_IMAGE=mirror.gcr.io/library/rust:1.99-slim-bookworm
# when Docker Hub rate-limits.
ARG RUST_IMAGE=rust:1.99-slim-bookworm
FROM ${RUST_IMAGE} AS build
# protoc: the LND rail's build script generates its gRPC client.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p caparra-gate -p bnap-signer-process \
    && mkdir -p /out \
    && cp target/release/caparra-gate target/release/bnap-signer /out/

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/caparra-gate /usr/local/bin/caparra-gate
COPY --from=build /out/bnap-signer /usr/local/bin/bnap-signer
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/caparra-gate"]
CMD ["run", "--config", "/etc/caparra/gate.toml"]
