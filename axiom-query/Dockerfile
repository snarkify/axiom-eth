# Use a smaller, specific version of the Rust image for building
FROM --platform=linux/amd64 rust:latest as builder

# Create a new empty project
RUN USER=root cargo new --bin snarkify
WORKDIR /snarkify

# Copy over your manifests and source tree
COPY Cargo.toml Cargo.lock rust-toolchain ./
COPY axiom-codec ./axiom-codec
COPY axiom-core ./axiom-core
COPY axiom-eth ./axiom-eth
COPY axiom-query ./axiom-query

# Cache dependencies by building a dummy project
RUN cargo build --package axiom-query --release --bin snarkify

# Use a slim variant for the runtime stage to reduce size
FROM --platform=linux/amd64 ubuntu:22.04

# Copy the build artifact from the build stage
COPY --from=builder /snarkify/target/release/snarkify /usr/local/bin/snarkify


# Set the startup command to run your binary
CMD ["/usr/local/bin/snarkify"]
