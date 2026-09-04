# The FFI shared library, built from THIS repo at the commit being released.
#
# It used to be built downstream: a consumer cloned this repo inside its own
# Docker build, at a commit named in an ARG it had to bump by hand. That ARG sat
# three releases behind for months -- the engine it shipped had neither
# ends_with nor the JSON lookup functions -- and nothing failed, because the
# only thing asserting which engine was in the image was the ARG itself.
#
# Building it here removes the class: the image is produced by the source it
# contains, tagged with the version that source declares.
#
# The layout is fixed by the existing consumers: /tmp/libwirefilter_ffi.so, so
# `COPY --from=wirefilter /tmp/libwirefilter_ffi.so` keeps working unchanged.

ARG DEBIAN_TAG="trixie-20260610"

FROM rust:1-slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The whole tree in one layer. A manifests-first copy would be pointless here --
# `COPY . .` follows immediately, so nothing is cached that the source copy does
# not invalidate -- and it was also wrong: the fuzz members are subdirectories
# (fuzz/bytes, fuzz/map-keys, fuzz/raw-string), not a flat fuzz/Cargo.toml, so
# it failed outright. Layer caching for the dependency build comes from the
# registry cache in CI, not from splitting this.
COPY . .

# --locked: the lockfile in this repo is the one the release was tested with, so
# a resolver picking something newer at image-build time would ship an engine
# nobody ran.
RUN cargo build --release --locked -p wirefilter-ffi \
    && cp target/release/libwirefilter_ffi.so /tmp/libwirefilter_ffi.so \
    && test -s /tmp/libwirefilter_ffi.so

FROM debian:${DEBIAN_TAG}

# Not a runnable image: it exists to be copied out of, by `--build-context` or a
# `COPY --from=`. No entrypoint, because there is nothing here to run.
COPY --from=builder /tmp/libwirefilter_ffi.so /tmp/libwirefilter_ffi.so
