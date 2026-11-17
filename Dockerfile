# Minimalist Linux (Alpine + musl) image that runs the full falcon-rs test
# suite. Building the image *is* the test run: any failing test, clippy lint,
# or formatting drift fails `docker build`.
#
#   docker build -t falcon-rs-test .          # build + run the whole suite
#   docker run --rm falcon-rs-test            # re-run the suite in the image
#
# Uses current stable Rust. The crate MSRV (Cargo.toml `rust-version`, 1.84)
# applies to library consumers and is verified separately by `cargo check`; the
# dev-dependencies (criterion → getrandom 0.4) require a newer toolchain to
# build the test/bench harness, so the test image tracks stable.
# Pin by digest for reproducible builds (`FROM rust:<ver>-alpine@sha256:...`).
FROM rust:alpine

# musl-dev provides the C runtime/headers cargo needs to link test binaries on
# Alpine; the extra components let the image run the same gates as CI.
RUN apk add --no-cache musl-dev && \
    rustup component add clippy rustfmt

WORKDIR /falcon

# Unprivileged user: nothing here needs root after the toolchain setup.
RUN adduser -D falcon
COPY --chown=falcon:falcon . .
USER falcon

# Fail the build on any formatting drift or lint before running tests.
# --locked everywhere: the committed Cargo.lock is what gets tested.
RUN cargo fmt --check
RUN cargo clippy --locked --all-targets --all-features -- -D warnings

# Run the whole suite: default features, plus the serde feature (matches CI),
# and confirm the no_std build still links.
RUN cargo test --locked --release
RUN cargo test --locked --release --all-features
RUN cargo build --locked --no-default-features

# Default command re-runs the full-feature suite when the image is started.
CMD ["cargo", "test", "--locked", "--release", "--all-features"]
