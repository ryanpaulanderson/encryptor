FROM rust:1.87

# Install dependencies for AFL++ and building
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      afl++ \
      libssl-dev \
      pkg-config \
      uuid-runtime && \
    rm -rf /var/lib/apt/lists/*

# Install the Rust plugin for AFL++
RUN cargo +stable install cargo-afl --locked

# Build the AFL++ runtime support for the stable toolchain
RUN cargo +stable afl config --build --force

# Set working directory to project root
WORKDIR /usr/src/encryptor

# Copy project files
COPY . .

# Build the AFL-instrumented harness in release mode
RUN cd fuzz && \
    cargo +stable afl build --release --features afl --bin encryptor_afl

# Create minimal seed corpus using a UUID
RUN mkdir -p fuzz/in fuzz/out && \
    uuidgen > fuzz/in/seed1

# Default command: run afl-fuzz from the fuzz directory
CMD ["bash", "-lc", "cd fuzz && afl-fuzz -i in -o out -- ./target/release/encryptor_afl"]