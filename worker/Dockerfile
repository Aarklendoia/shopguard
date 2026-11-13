# Local build: docker build -t shopguard-worker worker/
# Releases are built by CI from binaries cross-compiled with cargo-zigbuild
# (see Dockerfile.release and .github/workflows/release.yml).

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# musl target: a fully static binary that runs on an empty image
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/shopguard-worker /shopguard-worker
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/shopguard-worker", "healthcheck"]
ENTRYPOINT ["/shopguard-worker"]
